import axios from 'axios'
import { TestState } from './test_state'
import { deriveAuthenticationKey, deriveEncryptionKeyFromSeed } from './utils'
import * as Kilt from '@kiltprotocol/sdk-js'
import { toHex } from '@smithy/util-hex-encoding'
import {
  CREDENTIAL,
  DID_AUTH_KEY_URL,
  DID_KEY_AGREEMENT_URL,
  JWT_SECRET,
  OPENDID_URL,
  REQUIRED_CTYPE_HASH,
} from '../test_config'
import { EncryptedMessage, Requirments } from './types'
import { expect } from 'vitest'
import * as jsonwebtoken from 'jsonwebtoken'

import 'dotenv/config'
const mnemonic = process.env.SEED as string

if (!mnemonic) {
  throw new Error('mnemonic is not set')
}

export const credentialUrl = new URL('api/v1/credentials', OPENDID_URL)

/**
 * Get Request for `/credentials`
 */
export async function authenticationGet(testState: TestState): Promise<Requirments> {
  const response = await axios.get(credentialUrl.toString(), { headers: { Cookie: testState.getCookie() } })
  testState.setCookie(response)

  const decrypted = testState.decrypt(response.data.ciphertext, response.data.nonce)
  const requirements = JSON.parse(decrypted) as Requirments

  expect(requirements.body.type).toBe('request-credential')
  expect(requirements.body.content.cTypes[0].cTypeHash).toBe(REQUIRED_CTYPE_HASH)
  expect(requirements.body.content.cTypes[0].requiredProperties[0]).toBe('Email')
  return requirements
}

export async function authentication(testState: TestState, implicit = false) {
  const requirements = await authenticationGet(testState)
  const seed = Kilt.Utils.Crypto.mnemonicToMiniSecret(mnemonic)
  const key = deriveEncryptionKeyFromSeed(seed)
  const authenticationKey = deriveAuthenticationKey(seed)

  const presentation = await Kilt.Credential.createPresentation({
    credential: CREDENTIAL,
    signCallback: sign,
    challenge: requirements.body.content.challenge,
  })

  async function sign({ data }: Kilt.SignRequestData) {
    const signature = authenticationKey.sign(data, { withType: false })
    const keyUri = DID_AUTH_KEY_URL as Kilt.DidResourceUri
    const keyType = authenticationKey.type

    return {
      signature,
      keyUri,
      keyType,
    }
  }

  const payload = {
    body: { content: [presentation], type: 'credential' },
    createdAt: 0,
    sender: '-',
    receiver: '-',
    messageId: 'abc123',
  }

  const encrypted = Kilt.Utils.Crypto.encryptAsymmetric(
    JSON.stringify(payload),
    testState.getOpenDidKeyAgreement().publicKey,
    key.secretKey,
  )
  const postRequestBody: EncryptedMessage = {
    ciphertext: '0x' + toHex(encrypted.box),
    senderKeyUri: DID_KEY_AGREEMENT_URL,
    receiverKeyUri: '-',
    nonce: '0x' + toHex(encrypted.nonce),
  }

  const cookie = testState.getCookie()
  const response = await axios.post(credentialUrl.toString(), postRequestBody, {
    headers: { Cookie: cookie },
    validateStatus: (status) => {
      return status == 204
    },
  })

  const url = new URL(response.headers.location)
  expect(url.origin).toBe('http://localhost:1606')
  expect(url.pathname).toBe('/callback.html')
  if (implicit) {
    const fragmentIdentifiers = new URLSearchParams(url.hash.replace('#', '?'))
    expect(fragmentIdentifiers.get('state')).toBe(TestState.STATE)
    expect(fragmentIdentifiers.get('token_type')).toBe('bearer')
    expect(fragmentIdentifiers.get('refresh_token')!.length).toBeGreaterThan(10)
    const idToken = fragmentIdentifiers.get('id_token') as string

    const decodedToken = jsonwebtoken.verify(idToken, JWT_SECRET) as jsonwebtoken.JwtPayload
    expect(decodedToken.nonce).toBe(TestState.NONCE)
  } else {
    expect(url.searchParams.get('state')).toBe(TestState.STATE)
    const code = url.searchParams.get('code')!
    expect(code.length).toBeGreaterThan(10)
    testState.setAuthCode(code)
  }
}
