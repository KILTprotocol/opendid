// check if url query parameter contain access_token and refresh_token and state
const params = new URLSearchParams(window.location.search);
const accessToken = params.get('access_token');
const refreshToken = params.get('refresh_token');
const state = params.get('state');
if (accessToken && refreshToken && state) {
    const fn = async ()=>{
        // hide button:
        const loginButton = document.getElementById('login');
        loginButton.style.display = 'none';

        // use token to access protected route
        const resp = await fetch('/protected', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });
        const greeting = document.createElement('h2');
        if (resp.status !== 200) {
            greeting.innerText = `Error: ${resp.status} ${resp.statusText}`;
            document.body.appendChild(greeting);
            return;
        }
        greeting.innerText = await resp.text();
        document.body.appendChild(greeting);
    };
    fn();    
}

// add click listener to button to trigger login
const loginButton = document.getElementById('login');
loginButton.addEventListener('click', () => {
    // redirect to kilt wallet login page
    const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    window.location.href = `http://localhost:3001/api/v1/authorize?response_type=id_token&client_id=test&redirect_uri=http://localhost:1606&scope=openid&state=${state}&nonce=${nonce}`;
});