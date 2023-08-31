import React from 'react';

declare global {
    interface Window {
        kilt: any;
    }
}

interface SessionData {
    dAppName: string;
    dAppEncryptionKeyUri: string;
    challenge: string;
}

function ExtensionSelector(props: { onSelect: (extension: object) => void, selectedExtension: object | null }) {
    const [extensions, setExtensions] = React.useState<any[]>([]);
    
    const gatherExtensions = async () => {
        let extensions = Object.values(window.kilt)
            .filter((extension: any) => typeof extension === 'object')
            .filter((extension: any) => extension.name && extension.version)
        setExtensions(extensions);
        props.onSelect(extensions[0] as object);
    };

    React.useEffect(() => {
        gatherExtensions();
        window.addEventListener('kilt-extension#initialized', () => {
            gatherExtensions();
        });
    }, []);

    return (
        <select onChange={(e) => {
            console.log('selected extension', e.target.value)
            props.onSelect(extensions.find((extension: any) => extension.name === e.target.value));
        }}>
            {extensions.map((extension: any) => (
                <option value={extension.name} key={extension.name}>{extension.name} {extension.version}</option>
            ))}
        </select>
    );
}


export function App() {

    const [extension, setExtension] = React.useState<any>(null);
    const [loginResponse, setLoginResponse] = React.useState({idToken: '', refreshToken: ''});
    const [error, setError] = React.useState('');

    React.useEffect(() => {
        // check for query parameters access_token and refresh_token
        const urlParams = new URLSearchParams(window.location.search)
        const idToken = urlParams.get('access_token')
        const refreshToken = urlParams.get('refresh_token')
        if (idToken && refreshToken) {
            setLoginResponse({idToken, refreshToken})
        }
    })

    async function startSession() {
        try {
            const challenge = await (await fetch('/api/v1/challenge')).json();
            console.log('got challenge from server', challenge);
            const session = await extension.startSession(challenge.dAppName, challenge.dAppEncryptionKeyUri, challenge.challenge);
            console.log('started session, posting to server', session);
            const response = await fetch('/api/v1/challenge', {
                method: 'POST',
                body: JSON.stringify({
                    encryptionKeyUri: session.encryptionKeyUri ?? session.encryptionKeyId,
                    encryptedChallenge: session.encryptedChallenge,
                    nonce: session.nonce
                }),
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });
            const data = await response.text();
            console.log('response to challenge answer', data);
            console.log('fetching credential requirements')
            const credentialRequirements = await (await fetch('/api/v1/credentials', {
                credentials: 'include'
            })).json();
            console.log('got credential requirements', credentialRequirements);
            const credentialResponse = await new Promise(async (resolve, reject) => {
                try {
                    await session.listen((credentialResponse) => {
                        resolve(credentialResponse);
                    });
                    await session.send(credentialRequirements);
                } catch (e) {
                    reject(e);
                }
            });
            
            console.log('posting credential to server', credentialResponse)
            let url = '/api/v1/credentials'
            // get redirect uri query
            let redirectUri = new URLSearchParams(window.location.search).get('redirect')
            if (redirectUri) {
                url = `${url}?redirect=${redirectUri}`
            }
            const credentialResponseResponse = await fetch(url, {
                method: 'POST',
                body: JSON.stringify(credentialResponse),
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            console.log('credentialResponseResponse', credentialResponseResponse)

            if (credentialResponseResponse.status > 400) {
                const credentialResponseData = await credentialResponseResponse.text();
                console.log('response to posted credential', credentialResponseData);
                setError(credentialResponseData);
                return
            }

            if (credentialResponseResponse.status === 204) {
                const uri = credentialResponseResponse.headers.get('Location')
                if (uri !== null) {
                    console.log('redirecting to', uri)
                    window.location.href = uri
                    return
                }
            }

            const credentialResponseData = await credentialResponseResponse.json();
            console.log('response to posted credential', credentialResponseData);
            setLoginResponse(credentialResponseData);            
        } catch (e) {
            console.error(e);
            setError(e.message);
        }
    }

    async function refresh() {
        try {
            let refreshToken = loginResponse.refreshToken
            const resp = await fetch('/api/v1/refresh', {
                method: 'POST',
                body: JSON.stringify({refreshToken}),
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            const respData = await resp.json()
            console.log('refresh response', respData)
            setLoginResponse(respData)
        } catch (e) {
            console.error(e);
            setError(e.message);
        }
    }

    // some styles to center the login form
    React.useEffect(() => {
        const style = document.createElement('style');
        style.innerHTML = `
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            #App {
                width: 400px;
                height: 400px;
                border: 1px solid black;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
            }

        `;
        document.head.appendChild(style);
    }, []);

    return (
        <div id="App">
            <h1>Login</h1>
            <p>
                <ExtensionSelector selectedExtension={extension} onSelect={(e) => {
                    console.log('selected extension', e);
                    setExtension(e)
                }} />
            </p>
            <div style={{display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center'}}>
                <p>
                    <button onClick={startSession}>Login</button>
                </p>
                {loginResponse.idToken !== '' && loginResponse.refreshToken !== '' && (
                <div>
                    <p><a href={'https://jwt.io?token='+loginResponse.idToken}>Inspect ID Token</a></p>
                    <p><a href={'https://jwt.io?token='+loginResponse.refreshToken}>Inspect Refresh Token</a></p>
                </div>)}
                {loginResponse.idToken !== '' && loginResponse.refreshToken !== '' && (
                    <p><button onClick={refresh}>Refresh</button></p>                
                )}
                <p>{error}</p>
            </div>
            
        </div>
    );
}
