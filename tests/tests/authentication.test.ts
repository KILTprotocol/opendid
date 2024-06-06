import { authenticationGet, credentialUrl } from './authentication'
import { TestState } from './test_state'
import { authorize } from './authorize'
import { challenge } from './challenge'
import axios from 'axios'
import { deriveEncryptionKeyFromSeed } from './utils'
import * as Kilt from '@kiltprotocol/sdk-js'
import { toHex } from '@smithy/util-hex-encoding'
import { CREDENTIAL, DID_KEY_AGREEMENT_URL } from '../test_config'
import { describe, it, expect } from 'vitest'
import 'dotenv/config'
import { EncryptedMessage } from './types'

const mnemonic = process.env.SEED as string

describe('Authentication', () => {
  it('should refuse unsigned presentation', async () => {
    const testState = new TestState()

    await authorize(testState)
    await challenge(testState)
    await authenticationGet(testState)

    const payload = {
      body: { content: [CREDENTIAL], type: 'credential' },
      createdAt: 0,
      sender: null,
      receiver: null,
      messageId: 0,
    }

    const seed = Kilt.Utils.Crypto.mnemonicToMiniSecret(mnemonic)
    const keyAgreementKey = deriveEncryptionKeyFromSeed(seed)
    const credentialString = JSON.stringify(payload)
    const encrypted = Kilt.Utils.Crypto.encryptAsymmetric(
      credentialString,
      testState.getOpenDidKeyAgreement().publicKey,
      keyAgreementKey.secretKey,
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
      validateStatus: () => true,
    })
    expect(response.status).toBe(400)
    expect(response.data).toBe('Failed to parse message')
  })
})
