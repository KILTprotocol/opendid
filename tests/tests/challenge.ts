import 'dotenv/config'
import axios, { AxiosResponse } from 'axios'
import { TestState } from './test_state'
import { resolveKeyDetails } from './utils'
import { fromHex } from '@smithy/util-hex-encoding'

const opendidEndpoint = process.env.OPENDID_URL
const challengeUrl = new URL('api/v1/challenge', opendidEndpoint)

export async function challenge(testState: TestState): Promise<AxiosResponse> {
  let cookie = testState.getCookie()
  let response = await axios.get(challengeUrl.toString(), { headers: { Cookie: cookie } })
  testState.setCookie(response)

  const keyDetails = await resolveKeyDetails(response.data.dAppEncryptionKeyUri)
  testState.setOpenDidKeyAgreement(keyDetails)

  const encrypted = testState.encrypt(fromHex(response.data.challenge.replace('0x', '')))

  const encryptionKeyUri = testState.getDidDocument().uri.toString()
  const encryptedChallenge = encrypted.box
  const nonce = encrypted.nonce
  const postRequestBody = {
    encryptionKeyUri,
    encryptedChallenge,
    nonce,
  }

  cookie = testState.getCookie()
  response = await axios.post(challengeUrl.toString(), postRequestBody, {
    headers: { Cookie: cookie },
  })
  testState.setCookie(response)
  return response
}
