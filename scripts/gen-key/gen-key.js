import { mnemonicToMiniSecret, sr25519PairFromSeed, keyExtractPath, keyFromPath, cryptoWaitReady, blake2AsU8a } from '@polkadot/util-crypto'
import { u8aToHex } from '@polkadot/util'
import { box_keyPair_fromSecretKey } from 'tweetnacl-ts'

async function main() {
    // get first command line argument
    await cryptoWaitReady()
    const mnemonic = process.argv[2]
    const seed = mnemonicToMiniSecret(mnemonic)
    const keypair = sr25519PairFromSeed(seed)
    const naclSeed = blake2AsU8a(keypair.secretKey)
    const naclPair = box_keyPair_fromSecretKey(naclSeed)
    console.log(JSON.stringify({ pubKey: u8aToHex(naclPair.publicKey), privKey: u8aToHex(naclPair.secretKey)}))
} 

main()