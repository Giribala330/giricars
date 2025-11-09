import os, re, datetime
from functools import wraps

from flask import Flask, request, jsonify, make_response, send_from_directory, abort
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# ---------- Config ----------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data.db")
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALGO = "HS256"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

app = Flask(__name__)

# Where our static files live when running locally (project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# ---------- Models ----------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    role = Column(String(10))       # "buyer" | "seller" | "admin"
    name = Column(String(120))
    age = Column(Integer)
    address = Column(Text)
    phone = Column(String(30))
    usermail = Column(String(120), unique=True, index=True)
    gmail = Column(String(120))
    password_hash = Column(String(255))
    status = Column(String(20), default="pending")  # pending | approved | restricted
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    cars = relationship("Car", back_populates="seller")

class Car(Base):
    __tablename__ = "cars"
    id = Column(Integer, primary_key=True)
    seller_id = Column(Integer, ForeignKey("users.id"))
    brand = Column(String(80))
    model = Column(String(120))
    model_year = Column(Integer)
    milage = Column(String(50))
    fuel_type = Column(String(30))
    ext_col = Column(String(40))
    int_col = Column(String(40))
    accident = Column(Text)
    price = Column(String(40))
    approved = Column(Boolean, default=False)  # by admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    seller = relationship("User", back_populates="cars")

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    car_id = Column(Integer, ForeignKey("cars.id"))
    buyer_id = Column(Integer, ForeignKey("users.id"))
    buyer_name = Column(String(120))
    buyer_address = Column(Text)
    buyer_phone = Column(String(30))
    needed_date = Column(String(40))
    status = Column(String(20), default="pending")  # pending | approved | declined
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    car = relationship("Car")
    buyer = relationship("User")

Base.metadata.create_all(engine)

# seed admin
def seed_admin():
    with SessionLocal() as db:
        exists = db.query(User).filter(User.usermail == "admin@carsdoor.com").first()
        if not exists:
            admin = User(
                role="admin",
                name="Admin",
                age=30,
                address="HQ",
                phone="0000000000",
                usermail="admin@carsdoor.com",
                gmail="admin@carsdoor.com",
                password_hash=generate_password_hash("admin@123"),
                status="approved",
            )
            db.add(admin)
            db.commit()
seed_admin()

# ---------- Helpers ----------
def make_token(user):
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "usermail": user.usermail,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def auth_required(roles=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = request.cookies.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                return jsonify({"error": "Unauthorized"}), 401
            try:
                data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            except Exception:
                return jsonify({"error": "Invalid token"}), 401

            with SessionLocal() as db:
                user = db.get(User, int(data["sub"]))
                if not user:
                    return jsonify({"error": "User not found"}), 404
                if user.status != "approved" and user.role != "admin":
                    return jsonify({"error": f"User status is {user.status}"}), 403
                if roles and user.role not in roles:
                    return jsonify({"error": "Forbidden"}), 403
                request.current_user = user
                return fn(*args, **kwargs)
        return wrapper
    return decorator

def valid_usermail(role, usermail):
    pattern = re.compile(rf"^{role}_[a-zA-Z0-9._-]+@carsdoor\.com$")
    return bool(pattern.match(usermail))

# ---------- API Routes ----------
@app.get("/api/health")
def health():
    return {"ok": True}

@app.post("/api/register")
def register():
    data = request.get_json() or {}
    role = data.get("role")
    if role not in ["buyer", "seller"]:
        return jsonify({"error": "role must be buyer or seller"}), 400

    usermail = data.get("usermail", "").strip()
    if not valid_usermail(role, usermail):
        return jsonify({"error": f"usermail must be like {role}_name@carsdoor.com"}), 400

    required = ["name", "age", "address", "phone", "gmail", "password"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    with SessionLocal() as db:
        if db.query(User).filter(User.usermail == usermail).first():
            return jsonify({"error": "usermail already exists"}), 409
        u = User(
            role=role,
            name=data["name"],
            age=int(data["age"]),
            address=data["address"],
            phone=data["phone"],
            usermail=usermail,
            gmail=data["gmail"],
            password_hash=generate_password_hash(data["password"]),
            status="pending",
        )
        db.add(u)
        db.commit()
        return jsonify({"message": "Registered. Wait for admin approval."})

@app.post("/api/login")
def login():
    data = request.get_json() or {}
    usermail = data.get("usermail", "").strip()
    password = data.get("password", "")

    with SessionLocal() as db:
        u = db.query(User).filter(User.usermail == usermail).first()
        if not u or not check_password_hash(u.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = make_token(u)
        resp = make_response({"message": "Logged in", "role": u.role})
        resp.set_cookie("token", token, httponly=True, secure=False, samesite="Lax", max_age=7 * 24 * 3600)
        return resp

@app.post("/api/logout")
def logout():
    resp = make_response({"message": "Logged out"})
    resp.set_cookie("token", "", max_age=0)
    return resp

@app.get("/api/me")
@auth_required()
def me():
    u = request.current_user
    return {
        "id": u.id,
        "role": u.role,
        "name": u.name,
        "status": u.status,
        "usermail": u.usermail,
        "gmail": u.gmail,
    }

# ----- Admin endpoints -----
@app.get("/api/admin/users")
@auth_required(roles=["admin"])
def admin_users():
    with SessionLocal() as db:
        users = db.query(User).filter(User.role.in_(["buyer", "seller"])).all()
        return {
            "users": [
                {"id": u.id, "role": u.role, "name": u.name, "usermail": u.usermail, "status": u.status}
                for u in users
            ]
        }

@app.post("/api/admin/approve-user")
@auth_required(roles=["admin"])
def admin_approve_user():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    approve = bool(data.get("approve", True))
    with SessionLocal() as db:
        u = db.get(User, user_id)
        if not u:
            return jsonify({"error": "User not found"}), 404
        u.status = "approved" if approve else "restricted"
        db.commit()
        return {"message": f"User {u.usermail} set to {u.status}"}

@app.post("/api/admin/restrict-user")
@auth_required(roles=["admin"])
def admin_restrict_user():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    with SessionLocal() as db:
        u = db.get(User, user_id)
        if not u:
            return jsonify({"error": "User not found"}), 404
        u.status = "restricted"
        db.commit()
        return {"message": f"User {u.usermail} restricted"}

@app.get("/api/admin/pending-cars")
@auth_required(roles=["admin"])
def admin_pending_cars():
    with SessionLocal() as db:
        cars = db.query(Car).filter(Car.approved == False).order_by(Car.created_at.desc()).all()
        out = []
        for c in cars:
            out.append({
                "id": c.id,
                "brand": c.brand,
                "model": c.model,
                "model_year": c.model_year,
                "milage": c.milage,
                "fuel_type": c.fuel_type,
                "ext_col": c.ext_col,
                "int_col": c.int_col,
                "accident": c.accident,
                "price": c.price,
                "seller_id": c.seller_id,
                "seller_name": c.seller.name if c.seller else None,
                "seller_phone": c.seller.phone if c.seller else None
            })
        return {"cars": out}

@app.post("/api/admin/approve-car")
@auth_required(roles=["admin"])
def admin_approve_car():
    data = request.get_json() or {}
    car_id = data.get("car_id")
    approve = bool(data.get("approve", True))
    with SessionLocal() as db:
        c = db.get(Car, car_id)
        if not c:
            return jsonify({"error": "Car not found"}), 404
        if approve:
            c.approved = True
            db.commit()
            return {"message": f"Car {c.id} approved"}
        else:
            # Reject: remove from queue so it no longer shows up
            db.delete(c)
            db.commit()
            return {"message": f"Car {car_id} rejected and removed"}

@app.get("/api/admin/orders")
@auth_required(roles=["admin"])
def admin_orders():
    with SessionLocal() as db:
        orders = db.query(Order).all()
        def pack(o):
            return {
                "id": o.id,
                "status": o.status,
                "needed_date": o.needed_date,
                "buyer_name": o.buyer_name,
                "buyer_phone": o.buyer_phone,
                "car_id": o.car_id,
                "car_brand": o.car.brand if o.car else None,
                "car_model": o.car.model if o.car else None,
            }
        return {"orders": [pack(o) for o in orders]}

@app.post("/api/admin/approve-order")
@auth_required(roles=["admin"])
def admin_approve_order():
    data = request.get_json() or {}
    order_id = data.get("order_id")
    approve = bool(data.get("approve", True))
    with SessionLocal() as db:
        o = db.get(Order, order_id)
        if not o:
            return jsonify({"error": "Order not found"}), 404
        o.status = "approved" if approve else "declined"
        db.commit()
        return {"message": "Order {0} set to {1}".format(o.id, o.status)}

# ----- Seller endpoints -----
@app.post("/api/seller/add-car")
@auth_required(roles=["seller"])
def seller_add_car():
    u = request.current_user
    data = request.get_json() or {}
    required = ["brand", "model", "model_year", "milage", "fuel_type", "ext_col", "int_col", "accident", "price"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    with SessionLocal() as db:
        c = Car(
            seller_id=u.id,
            brand=data["brand"],
            model=data["model"],
            model_year=int(data["model_year"]),
            milage=data["milage"],
            fuel_type=data["fuel_type"],
            ext_col=data["ext_col"],
            int_col=data["int_col"],
            accident=data["accident"],
            price=data["price"],
            approved=False,
        )
        db.add(c)
        db.commit()
        return {"message": "Car submitted for admin approval", "car_id": c.id}

@app.get("/api/seller/orders")
@auth_required(roles=["seller"])
def seller_orders():
    u = request.current_user
    with SessionLocal() as db:
        q = db.query(Order).join(Car, Order.car_id == Car.id).filter(Car.seller_id == u.id).all()
        res = [
            {
                "order_id": o.id,
                "status": o.status,
                "buyer_name": o.buyer_name,
                "buyer_phone": o.buyer_phone,
                "needed_date": o.needed_date,
                "car_id": o.car_id,
                "car_brand": o.car.brand if o.car else None,
                "car_model": o.car.model if o.car else None,
            }
            for o in q
        ]
        return {"orders": res}

# ----- Buyer endpoints -----
# Hide cars that already have an APPROVED order (sold)
@app.get("/api/cars")
def list_cars():
    with SessionLocal() as db:
        approved_subq = db.query(Order.car_id).filter(Order.status == "approved").subquery()
        cars = (
            db.query(Car)
              .filter(Car.approved == True, ~Car.id.in_(approved_subq))
              .order_by(Car.created_at.desc())
              .all()
        )
        out = []
        for c in cars:
            out.append(
                {
                    "id": c.id,
                    "brand": c.brand,
                    "model": c.model,
                    "model_year": c.model_year,
                    "milage": c.milage,
                    "fuel_type": c.fuel_type,
                    "ext_col": c.ext_col,
                    "int_col": c.int_col,
                    "accident": c.accident,
                    "price": c.price,
                    "seller_name": c.seller.name if c.seller else None,
                    "seller_phone": c.seller.phone if c.seller else None,
                }
            )
        return {"cars": out}

@app.post("/api/buyer/order")
@auth_required(roles=["buyer"])
def buyer_order():
    data = request.get_json() or {}
    required = ["car_id", "name", "address", "phone", "needed_date"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    with SessionLocal() as db:
        car = db.get(Car, int(data["car_id"]))
        if not car or not car.approved:
            return jsonify({"error": "Car not available"}), 400

        o = Order(
            car_id=car.id,
            buyer_id=request.current_user.id,
            buyer_name=data["name"],
            buyer_address=data["address"],
            buyer_phone=data["phone"],
            needed_date=data["needed_date"],
            status="pending",
        )
        db.add(o)
        db.commit()
        return {"message": "Order placed. Awaiting admin approval.", "order_id": o.id}

@app.get("/api/buyer/orders")
@auth_required(roles=["buyer"])
def buyer_orders_list():
    with SessionLocal() as db:
        q = (
            db.query(Order)
              .join(Car, Order.car_id == Car.id)
              .filter(Order.buyer_id == request.current_user.id)
              .order_by(Order.created_at.desc())
              .all()
        )
        return {"orders": [{
            "id": o.id,
            "status": o.status,
            "needed_date": o.needed_date,
            "car_id": o.car_id,
            "car_brand": o.car.brand if o.car else None,
            "car_model": o.car.model if o.car else None,
        } for o in q]}

# ---------- Static for LOCAL dev only ----------
@app.route("/")
def serve_index():
    return send_from_directory(PROJECT_ROOT, "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    path = os.path.join(PROJECT_ROOT, filename)
    if os.path.isfile(path):
        return send_from_directory(PROJECT_ROOT, filename)
    abort(404)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "3000")))
