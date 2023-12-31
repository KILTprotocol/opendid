// add click listener to button to trigger login
const loginButton = document.getElementById('login');
loginButton.addEventListener('click', () => {
    const clientId = document.getElementById('client-id').value;
    const nonce = document.cookie.split('; ').find(row => row.startsWith('nonce')).split('=')[1];
    const state = document.cookie.split('; ').find(row => row.startsWith('state')).split('=')[1];
    window.location.href = `http://localhost:3001/api/v1/authorize?response_type=id_token&client_id=${clientId}&redirect_uri=http://localhost:1606/callback.html&scope=openid&state=${state}&nonce=${nonce}`;
});
