import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Did, connect } from '@kiltprotocol/sdk-js';
import * as sha512 from 'js-sha512';

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

  const handleCredentialLogin = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      const form = event.currentTarget;
      const extension = new FormData(form).get('extension') as string;

      const session = await getSession(kilt[extension]);

      const credentialRequirements = await (
        await fetch('/api/v1/credentials', {
          credentials: 'include',
        })
      ).json();
      const getCredentialFromExtension = await new Promise(async (resolve, reject) => {
        try {
          await session.listen(async (credential) => {
            resolve(credential);
          });
          await session.send(credentialRequirements);
        } catch (e) {
          reject(e);
        }
      });

      const fetchCredential = await fetch(`/api/v1/credentials`, {
        method: 'POST',
        body: JSON.stringify(getCredentialFromExtension),
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      });

      if (fetchCredential.status >= 400) {
        const credentialResponseData = await fetchCredential.text();
        throw new Error(credentialResponseData);
      }

      if (fetchCredential.status === 204) {
        const uri = fetchCredential.headers.get('Location');
        if (uri !== null) {
          window.location.href = uri;
          return;
        }
      }
    },
    [kilt],
  );

  const handleSIOPV2Login = useCallback(
    async (nonce: string, event: FormEvent<HTMLFormElement>) => {
      connect(process.env.WSS_ENDPOINT ? process.env.WSS_ENDPOINT : 'wss://peregrine.kilt.io');

      const form = event.currentTarget;
      const extension = new FormData(form).get('extension') as string;
      const Dids = await kilt[extension].getDidList();

      const did = Dids[0].did;

      const didDocument = await Did.resolve(did);

      // jwt parts
      const nbf = Math.floor(Date.now() / 1000);
      const exp = nbf + 60;
      const kid = `${did}${didDocument?.document?.authentication[0].id}`;
      const kty = didDocument?.document?.authentication[0].type;
      // Not completely standard, but SR25519 is not commonly used for JWTs.
      const header = { alg: 'EdDSA', typ: 'JWT', crv: 'Ed25519', kid, kty };
      const body = { iss: did, sub: did, nonce, exp, nbf };

      //encoded + signature
      const headerEncoded = btoa(JSON.stringify(header));
      const bodyEncoded = btoa(JSON.stringify(body));
      const dataToSign = headerEncoded + '.' + bodyEncoded;

      const signData = await kilt[extension].signWithDid(sha512.sha512(dataToSign), did);

      // submit token
      const token = dataToSign + '.' + btoa(signData.signature);

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

      const response = await didLoginResponse.text();
      throw new Error(response);
    },
    [kilt],
  );

  const handleLogin = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const url = new URL(window.location.href);
      setError(false);
      try {
        const nonce = url.searchParams.get('nonce');
        if (nonce) {
          handleSIOPV2Login(nonce, event);
        } else {
          handleCredentialLogin(event);
        }
      } catch (e) {
        console.error(e);
        setError(true);
      }
    },
    [handleCredentialLogin, handleSIOPV2Login],
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
