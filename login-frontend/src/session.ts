import { DidUri } from '@kiltprotocol/sdk-js';

interface EncryptedMessage {
  receiverKeyUri: string;
  senderKeyUri: string;
  ciphertext: string;
  nonce: string;
  receivedAt?: number;
}

interface PubSubSession {
  listen: (callback: (message: EncryptedMessage) => Promise<void>) => Promise<void>;
  close: () => Promise<void>;
  send: (message: EncryptedMessage) => Promise<void>;
  encryptionKeyUri: string;
  encryptedChallenge: string;
  nonce: string;
}

export interface InjectedWindowProvider {
  startSession: (dAppName: string, dAppEncryptionKeyUri: string, challenge: string) => Promise<PubSubSession>;
  name: string;
  version: string;
  specVersion: '3.0';
  signWithDid: (data: string, didKeyUri: DidUri) => Promise<{ didKeyUri: string; signature: string }>;
  getDidList: () => Promise<Array<{ did: DidUri }>>;
}

export const apiWindow = window as unknown as {
  kilt: Record<string, InjectedWindowProvider>;
};

export function getCompatibleExtensions(): Array<string> {
  return Object.entries(apiWindow.kilt)
    .filter(([, provider]) => provider.specVersion.startsWith('3.'))
    .map(([name]) => name);
}

export async function getSession(provider: InjectedWindowProvider): Promise<PubSubSession> {
  if (!provider) {
    throw new Error('No provider');
  }

  const challenge = await (await fetch('/api/v1/challenge')).json();
  const session = await provider.startSession(challenge.dAppName, challenge.dAppEncryptionKeyUri, challenge.challenge);
  await fetch('/api/v1/challenge', {
    method: 'POST',
    body: JSON.stringify({
      encryptionKeyUri: session.encryptionKeyUri ?? session.encryptionKeyId,
      encryptedChallenge: session.encryptedChallenge,
      nonce: session.nonce,
    }),
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
  });

  return session;
}
