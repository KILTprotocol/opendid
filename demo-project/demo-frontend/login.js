// add click listeners to login buttons.
const loginButtonImplicit = document.getElementById('login-implicit');
loginButtonImplicit.addEventListener('click', () => {
  const clientId = getClientIdElement();
  const nonce = getNonce();
  const state = getState();
  window.location.href = `http://localhost:3001/api/v1/authorize?response_type=id_token&client_id=${clientId}&redirect_uri=http://localhost:1606/callback.html&scope=openid&state=${state}&nonce=${nonce}`;
});

const loginButtonAuthCode = document.getElementById('login-authorization-code');
loginButtonAuthCode.addEventListener('click', () => {
  const clientId = getClientIdElement();
  const nonce = getNonce();
  const state = getState();
  window.location.href = `http://localhost:3001/api/v1/authorize?response_type=code&client_id=${clientId}&redirect_uri=http://localhost:1606/callback.html&scope=openid&state=${state}&nonce=${nonce}`;
});

function getState() {
    return document.cookie.split('; ').find(row => row.startsWith('state')).split('=')[1];
}

function getNonce() {
    return document.cookie.split('; ').find(row => row.startsWith('nonce')).split('=')[1];
}

function getClientIdElement() {
    return document.getElementById('client-id').value;
}

