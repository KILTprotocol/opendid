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
    React.useEffect(() => {
        setExtensions(
            Object.values(window.kilt)
            .filter((extension: any) => typeof extension === 'object')
            .filter((extension: any) => extension.name && extension.version)
        );
        window.addEventListener('kilt-extension#initialized', () => {
            console.log('kilt-extension#initialized');
            setExtensions(
                Object.values(window.kilt)
                .filter((extension: any) => typeof extension === 'object')
                .filter((extension: any) => extension.name && extension.version)
            );
        });
    }, []);

    React.useEffect(() => {
        if (extensions.length > 0 && props.selectedExtension === null) {
            props.onSelect(extensions[0]);
        }
    });

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
    const [loginResponse, setLoginResponse] = React.useState({accessToken: '', refreshToken: ''});
    const [error, setError] = React.useState('');

    React.useEffect(() => {
        // check for query parameters access_token and refresh_token
        const urlParams = new URLSearchParams(window.location.search)
        const accessToken = urlParams.get('access_token')
        const refreshToken = urlParams.get('refresh_token')
        if (accessToken && refreshToken) {
            setLoginResponse({accessToken, refreshToken})
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
            // get redirect uri from input field
            const redirectUri = document.getElementById('redirect-uri') as HTMLInputElement
            if (redirectUri.value) {
                url = `${url}?redirect=${redirectUri.value}`
            }
            const credentialResponseResponse = await fetch(url, {
                method: 'POST',
                body: JSON.stringify(credentialResponse),
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });
            if (credentialResponseResponse.redirected) {
                window.location.href = credentialResponseResponse.url
                return
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

    return (
        <div>
            <ExtensionSelector selectedExtension={extension} onSelect={(e) => {
                console.log('selected extension', e);
                setExtension(e)
            }} />
            <input id="redirect-uri" type="text" value={window.location.origin}/>
            <button onClick={startSession}>Login</button>
            <button onClick={refresh}>Refresh</button>
            <p>Access Token: {loginResponse.accessToken}</p>
            <p>Refresh Token: {loginResponse.refreshToken}</p>
            <p>{error}</p>
        </div>
    );
}