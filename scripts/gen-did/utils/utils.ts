import * as Kilt from '@kiltprotocol/sdk-js'

import * as fs from 'fs'
import * as fsPromise from 'fs/promises'

import { u8aToHex } from '@polkadot/util'

import {
    blake2AsU8a,
    keyExtractPath,
    keyFromPath,
    mnemonicGenerate,
    mnemonicToMiniSecret,
    sr25519PairFromSeed,
} from '@polkadot/util-crypto'

export interface DidSecrets {
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

export async function checkAndWriteFile(didSecrets: object, filename: string) {
    if (fs.existsSync(filename)) {
        return console.error(`files ${filename} exist already`)
    }
    await fsPromise.writeFile(filename, JSON.stringify(didSecrets, null, 2))
    return console.debug(`Wrote ${filename}`)
}

export const signingKeyType = 'sr25519'

export function generateKeyAgreement(mnemonic: string): Kilt.KiltEncryptionKeypair {
    const secretKeyPair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic))
    const { path } = keyExtractPath('//did//keyAgreement//0')
    const { secretKey } = keyFromPath(secretKeyPair, path, signingKeyType)
    return Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(secretKey))
}

export function generateKeypairs(mnemonic = mnemonicGenerate()): {
    baseMnemonic: string
    authentication: Kilt.KiltKeyringPair
    keyAgreement: Kilt.KiltEncryptionKeypair
    assertionMethod: Kilt.KiltKeyringPair
} {
    const authentication = Kilt.Utils.Crypto.makeKeypairFromUri(mnemonic + '//did//0', signingKeyType)

    const assertionMethod = Kilt.Utils.Crypto.makeKeypairFromUri(mnemonic + '//did//assertion//0', signingKeyType)

    const keyAgreement = generateKeyAgreement(mnemonic)

    return {
        baseMnemonic: mnemonic,
        authentication: authentication,
        keyAgreement: keyAgreement,
        assertionMethod: assertionMethod,
    }
}

export function exportKeypairs(keypairs: {
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
