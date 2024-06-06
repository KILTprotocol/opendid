import axios from 'axios'
import { TestState } from './test_state'
import { CLIENT_ID, CLIENT_SECRET, JWT_SECRET, OPENDID_URL, REDIRECT_URI } from '../test_config'
import { expect } from 'vitest'
import * as jsonwebtoken from 'jsonwebtoken'

const tokenUrl = new URL('api/v1/token', OPENDID_URL)

export async function token(testState: TestState) {
  const reqParams = {
    grant_type: 'authorization_code',
    code: testState.getAuthCode(),
    redirect_uri: REDIRECT_URI,
    client_secret: CLIENT_SECRET,
    client_id: CLIENT_ID,
  } as Record<string, string>

  const params = new URLSearchParams()
  for (const key in reqParams) {
    params.append(key, reqParams[key])
  }
  const response = await axios.post(tokenUrl.toString(), params)
  expect(response.data.access_token.length).toBeGreaterThan(10)
  expect(response.data.token_type).toBe('bearer')
  expect(response.data.refresh_token.length).toBeGreaterThan(10)

  const decodedToken = jsonwebtoken.verify(response.data.id_token, JWT_SECRET) as jsonwebtoken.JwtPayload
  expect(decodedToken.nonce).toBe(TestState.NONCE)
}
