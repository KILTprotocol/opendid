import { FormEvent, useCallback, useEffect, useState } from 'react';
import React from 'react';
import * as Jose from "jose"


import './App.css';
// remove this stylesheet if you want to add your own custom styles
import './kilt/styles.css';
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
  const hasExtension = extensions.length > 0;

  const [error, setError] = useState(false);

  const handleCredentialLogin = async (event: FormEvent<HTMLFormElement>) => {

    const form = event.currentTarget;
    const extension = new FormData(form).get('extension') as string;

    const session = await getSession(kilt[extension]);

    const credentialRequirements = await (
      await fetch('/api/v1/credentials', {
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
    url = `${url}?redirect=${redirectUri}`;


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

  }



  const handleSIOPV2Login = async (nonce: string, event: FormEvent<HTMLFormElement>) => {
    const form = event.currentTarget;
    const extension = new FormData(form).get('extension') as string;

    let { didKeyUri, signature } = await kilt[extension].signWithDid(nonce);

    let [did, keyURI] = didKeyUri.split("#");

    const secret = new TextEncoder().encode(
      nonce
    );

    const token = await new Jose.SignJWT({ signature, keyURI })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setIssuer(did)
      .setSubject(did)
      .setExpirationTime("1h")
      .sign(secret)

    const url = `/api/v1/did/${token}`;

    const didLoginResponse = await fetch(url, {
      method: 'POST',
    });

    if (didLoginResponse.status >= 400) {
      const credentialResponseData = await didLoginResponse.text();
      throw new Error(credentialResponseData);
    }

    if (didLoginResponse.status === 204) {
      const uri = didLoginResponse.headers.get('Location');
      if (uri !== null) {
        window.location.href = uri;
        return;
      }
    }


  }


  const handleLogin = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const url = new URL(window.location.href);
      setError(false)
      try {
        const nonce = url.searchParams.get("nonce");
        if (nonce) {
          handleSIOPV2Login(nonce, event)
        } else {
          handleCredentialLogin(event);
        }
      }
      catch (e) {
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
