// Enhanced API helper with clear error messages
async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...opts
  });

  let data = null;
  try { data = await res.json(); } catch (e) {}

  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || `HTTP ${res.status}`;
    console.error('API error:', path, msg, data);
    alert(msg);
    throw new Error(msg);
  }
  return data || {};
}

function bg(el, url){ el.style.backgroundImage = `url('${url}')`; }
function setBG(url){ document.querySelector('.bg')?.style.setProperty('background-image', `url('${url}')`); }

async function ensureLoggedIn(){
  try{ const me = await api('/api/me'); return me; } catch(e){ return null; }
}

window._carsdoor = { api, bg, setBG, ensureLoggedIn };
