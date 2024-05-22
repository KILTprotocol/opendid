// get the id_token and refresh_token from the fragment part of the url
// and store them in the session storage
const fragmentParams = new URLSearchParams(window.location.hash.slice(1));
const idToken = fragmentParams.get('id_token');
const refreshToken = fragmentParams.get('refresh_token');
const state = fragmentParams.get('state');

const params = new URLSearchParams(window.location.search);
const authCode = params.get('code');

if (idToken && refreshToken && state) {
    const fn = async () => {
        // use token to access protected route
        const resp = await fetch('/protected', {
            headers: {
                Authorization: `Bearer ${idToken}`
            }
        });
        displayGreeting(resp)
    };
    fn();
}

if (authCode) {
    const fn = async () => {
        // use Authorization Code to access protected route.
        // The backend will exchange the Authorization Code for an id_token.
        const resp = await fetch('/protected/AuthorizationCode', {
            method: "POST",
            headers: [["Content-Type", "application/json"]],
            body: JSON.stringify({
                auth_code: authCode
            })
        });
        await displayGreeting(resp)
    };
    fn();
}

async function displayGreeting(resp) {
    const greeting = document.createElement('h2');
    if (resp.status !== 200) {
        greeting.innerText = `Error: ${resp.status} ${resp.statusText}`;
        document.body.appendChild(greeting);
        return;
    }
    greeting.innerText = await resp.text();
    document.body.appendChild(greeting);
}
