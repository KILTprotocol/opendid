import { FormEvent, Fragment, useCallback, useEffect, useState } from 'react';
import './App.css';
import { apiWindow, getCompatibleExtensions, getSession } from './session';

function useCompatibleExtensions() {
  const [extensions, setExtensions] = useState(getCompatibleExtensions());
  useEffect(() => {
    function handler() {
      setExtensions(getCompatibleExtensions());
    }
    window.dispatchEvent(new CustomEvent('kilt-dapp#initialized'));
    window.addEventListener('kilt-extension#initialized', handler);
    return () => window.removeEventListener('kilt-extension#initialized', handler);
  }, []);

  return { extensions };
}

export function App() {
  const { kilt } = apiWindow;

  const { extensions } = useCompatibleExtensions();

  const [loginResponse, setLoginResponse] = useState({ idToken: '', refreshToken: '' });
  const { idToken, refreshToken } = loginResponse;
  const isLoggedIn = Boolean(idToken) && Boolean(refreshToken);

  const [error, setError] = useState('');

  useEffect(() => {
    // check for query parameters access_token and refresh_token
    const urlParams = new URLSearchParams(window.location.search);
    const idToken = urlParams.get('access_token');
    const refreshToken = urlParams.get('refresh_token');
    if (idToken && refreshToken) {
      setLoginResponse({ idToken, refreshToken });
    }
  });

  const handleLogin = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    try {
      const form = event.currentTarget;
      const extension = new FormData(form).get('extension') as string;

      const session = await getSession(kilt[extension]);

      console.log('fetching credential requirements');
      const credentialRequirements = await (
        await fetch('/api/v1/credentials', {
          credentials: 'include',
        })
      ).json();
      console.log('got credential requirements', credentialRequirements);
      const credentialResponse = await new Promise(async (resolve, reject) => {
        try {
          await session.listen(async (credentialResponse) => {
            resolve(credentialResponse);
          });
          await session.send(credentialRequirements);
        } catch (e) {
          reject(e);
        }
      });

      console.log('posting credential to server', credentialResponse);
      let url = '/api/v1/credentials';
      // get redirect uri query
      let redirectUri = new URLSearchParams(window.location.search).get('redirect');
      if (redirectUri) {
        url = `${url}?redirect=${redirectUri}`;
      }
      const credentialResponseResponse = await fetch(url, {
        method: 'POST',
        body: JSON.stringify(credentialResponse),
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      });

      console.log('credentialResponseResponse', credentialResponseResponse);

      if (credentialResponseResponse.status > 400) {
        const credentialResponseData = await credentialResponseResponse.text();
        console.log('response to posted credential', credentialResponseData);
        setError(credentialResponseData);
        return;
      }

      if (credentialResponseResponse.status === 204) {
        const uri = credentialResponseResponse.headers.get('Location');
        if (uri !== null) {
          console.log('redirecting to', uri);
          window.location.href = uri;
          return;
        }
      }

      const credentialResponseData = await credentialResponseResponse.json();
      console.log('response to posted credential', credentialResponseData);
      setLoginResponse(credentialResponseData);
    } catch (e) {
      console.error(e);
      setError(e.message);
    }
  }, []);

  const handleRefresh = useCallback(async () => {
    try {
      const resp = await fetch('/api/v1/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
        headers: {
          'Content-Type': 'application/json',
        },
      });
      const respData = await resp.json();
      console.log('refresh response', respData);
      setLoginResponse(respData);
    } catch (e) {
      console.error(e);
      setError(e.message);
    }
  }, []);

  return (
    <div className="container">
      <h1>Login</h1>

      <form onSubmit={handleLogin} className="loginForm">
        <select name="extension" defaultValue={extensions[0]}>
          {extensions.map((extension) => (
            <option value={extension} key={extension} label={`${kilt[extension].name} ${kilt[extension].version}`} />
          ))}
        </select>

        <p>
          <button type="submit">Login</button>
        </p>
      </form>

      {isLoggedIn && (
        <Fragment>
          <p>
            <a href={`https://jwt.io?token=${idToken}`}>Inspect ID Token</a>
          </p>
          <p>
            <a href={`https://jwt.io?token=${refreshToken}`}>Inspect Refresh Token</a>
          </p>
          <p>
            <button type="button" onClick={handleRefresh}>
              Refresh
            </button>
          </p>
        </Fragment>
      )}

      <p>{error}</p>
    </div>
  );
}
