const loginButtonImplicit = document.getElementById('login-implicit');
authorizeOnButtonClick(loginButtonImplicit, "id_token")

const loginButtonAuthCode = document.getElementById('login-authorization-code');
authorizeOnButtonClick(loginButtonAuthCode, "code");

function authorizeOnButtonClick(button, responseType){
    button.addEventListener('click', () => {
      const clientId = document.getElementById('client-id').value;
      const nonce = document.cookie.split('; ').find(row => row.startsWith('nonce')).split('=')[1];
      const state = document.cookie.split('; ').find(row => row.startsWith('state')).split('=')[1];
      window.location.href = `http://localhost:3001/api/v1/authorize?response_type=${responseType}&client_id=${clientId}&redirect_uri=http://localhost:1606/callback.html&scope=openid&state=${state}&nonce=${nonce}`;
    });
}
