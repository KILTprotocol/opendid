import * as Kilt from '@kiltprotocol/sdk-js'
import * as fs from 'fs/promises'

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
    }
    attestation: {
        pubKey: string
        seed: string
    }
    keyAgreement: {
        pubKey: string
        seed: string
        privKey: string
    }
}

const signingKeyType = 'sr25519'

function generateKeyAgreement(mnemonic: string): Kilt.KiltEncryptionKeypair {
    const secretKeyPair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic))
    const { path } = keyExtractPath('//did//keyAgreement//0')
    const { secretKey } = keyFromPath(secretKeyPair, path, signingKeyType)
    return Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(secretKey))
}

function generateKeypairs(mnemonic = mnemonicGenerate()): {
    baseMnemonic: string
    authentication: Kilt.KiltKeyringPair
    keyAgreement: Kilt.KiltEncryptionKeypair
    assertionMethod: Kilt.KiltKeyringPair
} {
    console.log('2', mnemonic)
    const baseKey = Kilt.Utils.Crypto.makeKeypairFromSeed(mnemonicToMiniSecret(mnemonic), signingKeyType)

    const authentication = baseKey.derive('//did//0') as typeof baseKey

    const assertionMethod = baseKey.derive('//did//assertion//0') as typeof baseKey

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
        },
    }
}

async function writeDidSecretsFile(didSecrets: DidSecrets, filename: string) {
    await fs.writeFile(filename, JSON.stringify(didSecrets, null, 2))
}

async function main() {
    // connect to kilt node

    let endpoint = 'wss://peregrine.kilt.io/'
    if (process.env.ENDPOINT) {
        switch (process.env.ENDPOINT) {
            case 'spiritnet':
                endpoint = 'wss://spiritnet.kilt.io/'
                break
            case 'peregrine':
                endpoint = 'wss://peregrine.kilt.io/'
                break
            default:
                endpoint = process.env.ENDPOINT
        }
    }
    console.debug(`Connecting to ${endpoint}...`)

    const api = await Kilt.connect(endpoint)
    console.debug(`Connected to ${endpoint}`)
    // console.log('api', api.on)
    // get first command line argument as seed for the payment account and fail if not provided
    const paymentSeed = process.argv[2]
    console.debug(paymentSeed)
    if (!paymentSeed) {
        // console.error('Please provide a seed for the payment account as first command line argument.');
        console.error('Payment seed not found')
        process.exit(1)
    }

    const paymentKeyPair = Kilt.Utils.Crypto.makeKeypairFromUri(paymentSeed, signingKeyType)
    console.debug(`Payment account address: ${paymentKeyPair.address}`)
    // get the balance of the payment account
    const accountInfo = await api.query.system.account(paymentKeyPair.address)
    console.debug(`Payment account balance: ${accountInfo.data.free}`)

    const keypairs = generateKeypairs()
    const didSecrets = exportKeypairs(keypairs)
    await writeDidSecretsFile(didSecrets, 'did-secrets.json')
    console.debug(`Wrote did-secrets.json`)
    const getStoreTxSignCallback: Kilt.Did.GetStoreTxSignCallback = async ({ data }) => ({
        signature: keypairs.authentication.sign(data),
        keyType: keypairs.authentication.type,
    })
    let result = await Kilt.Did.resolve(`did:kilt:${keypairs.authentication.address}`)
    console.debug(`Resolved DID ${keypairs.authentication.address} from chain`)
    if (!result) {
        // register the DID on chain
        console.debug(`Registering DID ${keypairs.authentication.address} on chain`)
        const fullDidCreationTx = await Kilt.Did.getStoreTx(
            {
                authentication: [{ publicKey: keypairs.authentication.publicKey, type: signingKeyType }],
                assertionMethod: [{ publicKey: keypairs.assertionMethod.publicKey, type: signingKeyType }],
                keyAgreement: [{ publicKey: keypairs.keyAgreement.publicKey, type: 'x25519' }],
            },
            paymentKeyPair.address,
            getStoreTxSignCallback
        )

        try {
            await Kilt.Blockchain.signAndSubmitTx(fullDidCreationTx, paymentKeyPair)
            console.debug(`Registered DID ${keypairs.authentication.address} on chain`)
        } catch (error) {
            console.error(error)
            process.exit(1)
        }

        result = await Kilt.Did.resolve(`did:kilt:${keypairs.authentication.address}`)
    }
    // write the DID document to a file
    await fs.writeFile('did-document.json', JSON.stringify(result.document, null, 2))

    await Kilt.disconnect()
}

main().catch((e) => {
    console.error(e)
    process.exit(1)
})
