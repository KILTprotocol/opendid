// get the id_token and refresh_token from the fragment part of the url
// and store them in the session storage
const params = new URLSearchParams(window.location.hash.slice(1));
const idToken = params.get('id_token');
const refreshToken = params.get('refresh_token');
const state = params.get('state');
const code = params.get('code')

if (!code && idToken && refreshToken && state) {
  const fn = async () => {
    // use token to access protected route
    const resp = await fetch('/protected', {
      headers: {
        Authorization: `Bearer ${idToken}`
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

if (code) {
  const fn = async () => {
    // use token to access protected route
    const resp = await fetch('/protected/AuthorizationCode', {
      method: "POST",
      headers: [["Content-Type", "application/json"]],
      body: JSON.stringify({
        Authorizationcode: code
      })
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
