import { FormEvent, useCallback, useEffect, useState } from 'react';
import './App.css';

// remove this stylesheet if you want to add your own custom styles
import './kilt/styles.css';

import { apiWindow, getCompatibleExtensions, getSession } from './session';
import React from 'react';

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
  const hasExtension = extensions.length > 0;

  const [error, setError] = useState(false);

  const handleLogin = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setError(false);

      try {
        const form = event.currentTarget;
        const extension = new FormData(form).get('extension') as string;

        const session = await getSession(kilt[extension]);

        const credentialRequirements = await (
          await fetch('http://0.0.0.0:3000/api/v1/credentials', {
            credentials: 'include',
          })
        ).json();
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

        let url = '/api/v1/credentials';
        // get redirect uri query
        const redirectUri = new URLSearchParams(window.location.search).get('redirect');
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

        if (credentialResponseResponse.status >= 400) {
          const credentialResponseData = await credentialResponseResponse.text();
          throw new Error(credentialResponseData);
        }

        if (credentialResponseResponse.status === 204) {
          const uri = credentialResponseResponse.headers.get('Location');
          if (uri !== null) {
            window.location.href = uri;
            return;
          }
        }
      } catch (e) {
        console.error(e);
        setError(true);
      }
    },
    [kilt],
  );

  return (
    <div className="app">
      <main className="main">
        <div className="loginContainer">
          <h1 className="heading">Log in with KILT</h1>

          {hasExtension && (
            <form onSubmit={handleLogin}>
              <select className="select" name="extension" defaultValue={extensions[0]}>
                {extensions.map((extension) => (
                  <option value={extension} key={extension} label={kilt[extension].name} />
                ))}
              </select>

              <button className="button" type="submit">
                Continue
              </button>

              {error && <p>Error</p>}
            </form>
          )}

          {!hasExtension && (
            <div>
              <p className="noWallet">Sorry, no identity wallet found!</p>
              <p>
                Please install a{' '}
                <a className="link" href="https://www.sporran.org/">
                  wallet
                </a>
              </p>
            </div>
          )}
        </div>
      </main>

      <footer className="footer"></footer>
    </div>
  );
}
