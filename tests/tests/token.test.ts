import { authentication } from './authentication'
import { TestState } from './test_state'
import { authorize } from './authorize'
import { challenge } from './challenge'
import { describe, expect, it } from 'vitest'
import { tokenUrl } from './token'
import { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI } from '../test_config'
import axios, { AxiosResponse } from 'axios'

describe('Token endpoint', async () => {
  it('should not accept invalid secret', async () => {
    const response = await tokenGet({ client_secret: 'invalid secret' })
    expect(response.status).toBe(401)
  })

  it('should not accept invalid grant_type', async () => {
    const response = await tokenGet({ grant_type: 'invalid type' })
    expect(response.status).toBe(400)
  })

  it('should not accept invalid redirect_uri', async () => {
    const response = await tokenGet({ redirect_uri: 'http://www.example.com/' })
    expect(response.status).toBe(400)
  })

  it('should not accept invalid client_id', async () => {
    const response = await tokenGet({ redirect_uri: 'invalid client id' })
    expect(response.status).toBe(400)
  })
})

async function tokenGet(paramsOverwrite: {
  grant_type?: string
  redirect_uri?: string
  client_secret?: string
  client_id?: string
}): Promise<AxiosResponse> {
  const testState = new TestState()

  await authorize(testState)
  await challenge(testState)
  await authentication(testState)

  let correctParams = {
    grant_type: 'authorization_code',
    code: testState.getAuthCode(),
    redirect_uri: REDIRECT_URI,
    client_secret: CLIENT_SECRET,
    client_id: CLIENT_ID,
  } as Record<string, string>
  correctParams = { ...correctParams, ...paramsOverwrite }

  const params = new URLSearchParams()
  for (const key in correctParams) {
    params.append(key, correctParams[key])
  }
  return await axios.post(tokenUrl.toString(), params, { validateStatus: () => true })
}
