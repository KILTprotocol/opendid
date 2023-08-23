const params = new URLSearchParams(window.location.search);
const accessToken = params.get('access_token');
const refreshToken = params.get('refresh_token');
const state = params.get('state');

if (accessToken && refreshToken && state) {
    const fn = async ()=>{
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
