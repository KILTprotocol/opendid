import axios from 'axios'
import 'dotenv/config'
import { TestState } from './test_state'
import { deriveAuthenticationKey, deriveEncryptionKeyFromSeed } from './utils'
import * as Kilt from '@kiltprotocol/sdk-js'
import { toHex } from '@smithy/util-hex-encoding'
import { CREDENTIAL, DID_AUTH_KEY_URL, DID_KEY_AGREEMENT_URL, OPENDID_URL, REQUIRED_CTYPE_HASH } from '../test_config'

const mnemonic = process.env.SEED as string
const credentialUrl = new URL('api/v1/credentials', OPENDID_URL)

interface EncryptedMessage {
  receiverKeyUri: string
  senderKeyUri: string
  ciphertext: string
  nonce: string
  receivedAt?: number
}

interface Requirments {
  body: {
    type: string
    content: {
      cTypes: [
        {
          cTypeHash: string
          trustedAttesters: string[]
          requiredProperties: string[]
        },
      ]
      challenge: string
    }
  }
  createdAt: number
  sender: string
  receiver: string
  messageId: string
  inReplyTo: null
  references: null
}

export async function authentication(testState: TestState) {
  let response = await axios.get(credentialUrl.toString(), { headers: { Cookie: testState.getCookie() } })
  testState.setCookie(response)

  const decrypted = testState.decrypt(response.data.ciphertext, response.data.nonce)
  const decryptedObject = JSON.parse(decrypted) as Requirments

  expect(decryptedObject.body.type).toBe('request-credential')
  expect(decryptedObject.body.content.cTypes[0].cTypeHash).toBe(REQUIRED_CTYPE_HASH)
  expect(decryptedObject.body.content.cTypes[0].requiredProperties[0]).toBe('Email')

  const seed = Kilt.Utils.Crypto.mnemonicToMiniSecret(mnemonic)
  const key = deriveEncryptionKeyFromSeed(seed)
  const authenticationKey = deriveAuthenticationKey(seed)

  const presentation = await Kilt.Credential.createPresentation({
    credential: CREDENTIAL,
    signCallback: sign,
    challenge: decryptedObject.body.content.challenge,
  })

  const toSend = {
    body: { content: [presentation], type: 'credential' },
    createdAt: 0,
    sender: '-',
    receiver: '-',
    messageId: '1234',
  }

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

  const credentialString = JSON.stringify(toSend)
  const encrypted = Kilt.Utils.Crypto.encryptAsymmetric(
    credentialString,
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
  response = await axios.post(credentialUrl.toString(), postRequestBody, {
    headers: { Cookie: cookie },
    validateStatus: (status) => {
      return status == 204
    },
  })
}
