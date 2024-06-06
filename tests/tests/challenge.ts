import axios, { AxiosResponse } from 'axios'
import { TestState } from './test_state'
import { resolveKeyDetails } from './utils'
import { fromHex } from '@smithy/util-hex-encoding'
import { OPENDID_URL } from '../test_config'
import { expect  } from 'vitest'

const challengeUrl = new URL('api/v1/challenge', OPENDID_URL)

export async function challenge(testState: TestState, useWrongChallenge = false): Promise<AxiosResponse> {
  let cookie = testState.getCookie()
  let response = await axios.get(challengeUrl.toString(), { headers: { Cookie: cookie } })
  testState.setCookie(response)

  const keyDetails = await resolveKeyDetails(response.data.dAppEncryptionKeyUri)
  testState.setOpenDidKeyAgreement(keyDetails)
  expect(response.data.challenge.length).toBeGreaterThan(10)

  // Encrypt challenge from `response` and send it back.
  const challenge = useWrongChallenge ? '68656C6C6F20776F726C64' : response.data.challenge.replace('0x', '')
  const encrypted = testState.encrypt(fromHex(challenge))
  const encryptionKeyUri = testState.getDidDocument().uri.toString()
  const encryptedChallenge = encrypted.box
  const nonce = encrypted.nonce
  const postRequestBody = {
    encryptionKeyUri,
    encryptedChallenge,
    nonce,
  }

  cookie = testState.getCookie()
  if (useWrongChallenge) {
    response = await axios.post(challengeUrl.toString(), postRequestBody, {
      headers: { Cookie: cookie },
      validateStatus: (status) => {
        return status == 401
      },
    })
    expect(response.data).toBe("Invalid challenge: Challenge doesn't match")
  } else {
    response = await axios.post(challengeUrl.toString(), postRequestBody, {
      headers: { Cookie: cookie },
    })
    expect(response.data).toBe('Challenge accepted')
    testState.setCookie(response)
  }
  return response
}
