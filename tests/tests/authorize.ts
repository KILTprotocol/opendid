import axios, { AxiosResponse } from 'axios'
import { addQueryParamsToUrl } from './utils'
import { TestState } from './test_state'
import { CLIENT_ID, OPENDID_URL, REDIRECT_URI } from '../test_config'
import { expect } from 'vitest'

const authorizeUrl = new URL('api/v1/authorize', OPENDID_URL)

/**
 * Get request of `/authorize`
 *
 * @param [implicit=false] set it to `true` to start an Implicit Flow, otherwise Authorization Code Flow.
 */
export async function authorize(testState: TestState, implicit: boolean = false): Promise<AxiosResponse> {
  const reqParams = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: implicit ? 'id_token' : 'code',
    scope: 'opendid',
    state: TestState.STATE,
    nonce: TestState.NONCE,
  }
  const urlWithParams = addQueryParamsToUrl(authorizeUrl, reqParams)
  // Don't redirect, and don't throw on status 302.
  const response = await axios.get(urlWithParams.toString(), {
    maxRedirects: 0,
    validateStatus: () => true,
  })
  expect(response.status).toBe(302)
  testState.setCookie(response)
  expect(response.headers.location).toEqual('/')
  expect(response.data).toEqual('')
  return response
}
