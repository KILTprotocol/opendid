import * as Kilt from '@kiltprotocol/sdk-js'
import * as fs from 'fs/promises';

import {
    blake2AsU8a,
    keyExtractPath,
    keyFromPath,
    mnemonicGenerate,
    mnemonicToMiniSecret,
    sr25519PairFromSeed,
} from '@polkadot/util-crypto'

import { u8aToHex } from '@polkadot/util'

interface DidSecrets {
    did: string
    authentication: {
        pubKey: string
        seed: string
    },
    attestation: {
        pubKey: string
        seed: string
    },
    keyAgreement: {
        pubKey: string
        seed: string
        privKey: string
    }
}

function generateKeyAgreement(mnemonic: string): Kilt.KiltEncryptionKeypair {
    const secretKeyPair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic))
    const { path } = keyExtractPath('//did//keyAgreement//0')
    const { secretKey } = keyFromPath(secretKeyPair, path, 'sr25519')
    return Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(secretKey))
}

function generateKeypairs(mnemonic = mnemonicGenerate()): {
    baseMnemonic: string
    authentication: Kilt.KiltKeyringPair
    keyAgreement: Kilt.KiltEncryptionKeypair
    assertionMethod: Kilt.KiltKeyringPair
} {
    const account = Kilt.Utils.Crypto.makeKeypairFromSeed(
        mnemonicToMiniSecret(mnemonic),
        'sr25519'
    )

    const authentication = {
        ...account.derive('//did//0'),
        type: 'sr25519'
    } as Kilt.KiltKeyringPair & {
        type: 'sr25519'
    }

    const assertionMethod = {
        ...account.derive('//did//assertion//0'),
        type: 'sr25519'
    } as Kilt.KiltKeyringPair

    const keyAgreement = generateKeyAgreement(mnemonic)

    return {
        baseMnemonic: mnemonic,
        authentication: authentication,
        keyAgreement: keyAgreement,
        assertionMethod: assertionMethod,
    }
}

function exportKeypairs(keypairs: {
    baseMnemonic: string
    authentication: Kilt.KiltKeyringPair
    keyAgreement: Kilt.KiltEncryptionKeypair
    assertionMethod: Kilt.KiltKeyringPair
}): DidSecrets {
    return {
        did: `did:kilt:${keypairs.authentication.address}`,
        authentication: {
            pubKey: keypairs.authentication.address,
            seed: keypairs.baseMnemonic + '//did//0',
        },
        attestation: {
            pubKey: keypairs.assertionMethod.address,
            seed: keypairs.baseMnemonic + '//did//assertion//0',
        },
        keyAgreement: {
            pubKey: u8aToHex(keypairs.keyAgreement.publicKey),
            seed: keypairs.baseMnemonic + '//did//keyAgreement//0',
            privKey: u8aToHex(keypairs.keyAgreement.secretKey),
        }
    }
}

async function writeDidSecretsFile(didSecrets: DidSecrets, filename: string) {
    await fs.writeFile(filename, JSON.stringify(didSecrets, null, 2));
}


async function main() {
    // connect to kilt node
    let endpoint = 'wss://spiritnet.kilt.io/';
    if (process.env.ENDPOINT) {
        switch (process.env.ENDPOINT) {
            case 'spiritnet': endpoint = 'wss://spiritnet.kilt.io/'; break;
            case 'peregrine': endpoint = 'wss://peregrine.kilt.io/'; break;
            default: endpoint = process.env.ENDPOINT;
        }
    }
    console.debug(`Connecting to ${endpoint}...`);
    const api = await Kilt.connect(endpoint);
    console.debug(`Connected to ${endpoint}`);

    // get first command line argument as seed for the payment account and fail if not provided
    const paymentSeed = process.argv[2];
    if (!paymentSeed) {
        // console.error('Please provide a seed for the payment account as first command line argument.');
        process.exit(1);
    }
    let paymentKeyPair = Kilt.Utils.Crypto.makeKeypairFromSeed(
        mnemonicToMiniSecret(paymentSeed),
        'sr25519',
    );
    console.debug(`Payment account address: ${paymentKeyPair.address}`);
    // get the balance of the payment account
    const accountInfo = await api.query.system.account(paymentKeyPair.address);
    console.debug(`Payment account balance: ${accountInfo.data.free}`);

    const keypairs = generateKeypairs();
    const didSecrets = exportKeypairs(keypairs);
    await writeDidSecretsFile(didSecrets, 'did-secrets.json');
    console.debug(`Wrote did-secrets.json`);

    let signCallback = (signData: Kilt.SignRequestData): Promise<Kilt.SignResponseData> => {
        return new Promise<Kilt.SignResponseData>((resolve, reject) => {
            const signResponseData: Kilt.SignResponseData = {
                signature: keypairs.authentication.sign(signData.data),
                keyType: keypairs.authentication.type,
                keyUri: `did:kilt:${keypairs.authentication.address}#lolidontknow`,
            };
            resolve(signResponseData);
        });
    };

    // register the DID on chain
    console.debug(`Registering DID ${keypairs.authentication.address} on chain`);
    const fullDidCreationTx = await Kilt.Did.getStoreTx({
        authentication: [{publicKey: keypairs.authentication.publicKey, type: 'sr25519'}],
        assertionMethod: [{publicKey: keypairs.assertionMethod.publicKey, type: 'sr25519'}],
        keyAgreement: [{publicKey: keypairs.keyAgreement.publicKey, type: 'x25519'}],
    },
        paymentKeyPair.address,
        signCallback
    );
    try {
        await Kilt.Blockchain.signAndSubmitTx(fullDidCreationTx, paymentKeyPair);
        console.debug(`Registered DID ${keypairs.authentication.address} on chain`);
    } catch (error) {
        // console.error(error);
        process.exit(1);
    }
    let result = await Kilt.Did.resolve(`did:kilt:${keypairs.authentication.address}`);
    console.debug(`Resolved DID ${keypairs.authentication.address} from chain`);
    // write the DID document to a file
    await fs.writeFile('did-document.json', JSON.stringify(result.document, null, 2));

    await Kilt.disconnect();
}

try {
    main();
} catch (error) {
    console.error(error);
    process.exit(1);
}
