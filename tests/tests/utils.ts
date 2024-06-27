import * as Kilt from '@kiltprotocol/sdk-js'
import { blake2AsU8a, keyExtractPath, keyFromPath, sr25519PairFromSeed } from '@polkadot/util-crypto'

/**
 * Conventient method to add query paramets to a URL.
 */
export function addQueryParamsToUrl(url: URL, paramsObj: Record<string, string>): URL {
  const params = new URLSearchParams()

  for (const key in paramsObj) {
    params.append(key, paramsObj[key])
  }
  return new URL(`${url}?${params.toString()}`)
}

/**
 * Resolves the DID Key through it's DID URL.
 */
export async function resolveKeyDetails(url: Kilt.DidResourceUri): Promise<Kilt.ResolvedDidKey> {
  await Kilt.connect('wss://peregrine.kilt.io/')
  const keyDetails: Kilt.ResolvedDidKey = await Kilt.Did.resolveKey(url)
  await Kilt.disconnect()
  return keyDetails
}

/**
 * Derives KeyAgreement keys from a seed using the derivation path in Sporran.
 */
export function deriveEncryptionKeyFromSeed(seed: Uint8Array): Kilt.KiltEncryptionKeypair {
  const keypair = sr25519PairFromSeed(seed)
  const { path } = keyExtractPath('//did//keyAgreement//0')
  const { secretKey } = keyFromPath(keypair, path, 'sr25519')
  return Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(secretKey))
}

/**
 * Derives Authentication keys from a seed using the derivation path in Sporran.
 */
export function deriveAuthenticationKey(seed: Uint8Array): Kilt.KiltKeyringPair {
  const baseKey = Kilt.Utils.Crypto.makeKeypairFromSeed(seed, 'sr25519')
  return baseKey.derive('//did//0') as typeof baseKey
}


// Use the utility function in your test cases
