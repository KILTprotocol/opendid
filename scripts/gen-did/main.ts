import * as Kilt from '@kiltprotocol/sdk-js'

import { checkAndWriteFile, exportKeypairs, generateKeypairs, signingKeyType } from './utils/utils'

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
    // get first command line argument as seed for the payment account and fail if not provided
    const paymentSeed = process.argv[2]
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
    await checkAndWriteFile(didSecrets, 'did-secrets.json')
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
    await checkAndWriteFile(result.document, 'did-document.json')

    await Kilt.disconnect()
}

main().catch((e) => {
    console.error(e)
    process.exit(1)
})
