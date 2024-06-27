import axios from 'axios'
import { addQueryParamsToUrl } from './utils'
import { TestState } from './test_state'
import { CLIENT_ID, OPENDID_URL, REDIRECT_URI } from '../test_config'
import { expect } from 'vitest'
import { describe, it } from 'vitest'

const authorizeUrl = new URL('api/v1/authorize', OPENDID_URL)

const ERROR_DESCRIPTION = 'error_description'
const STATE = 'state'
//Error Messages from ./routes/error.rs file
const ERR_MSG_INVALID_CLIENT_ID = 'Invalid client_id'
const ERR_MSG_INVALID_RESPONSE_TYPE = 'Invalid response_type'
const ERR_MSG_INVALID_NONCE = 'Invalid nonce'
const ERR_MSG_INVALID_REDIRECT_URI = 'Invalid redirect_uri'

describe('Authorize endpoint', async () => {
  it('should return error if client_id is given is invalid', async () => {
    const reqParams = {
      client_id: 'invalid_client',
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
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
    const locationUrl = new URL(response.headers.location)

    const errorDescription = locationUrl.searchParams.get(ERROR_DESCRIPTION)
    expect(errorDescription).toBe(ERR_MSG_INVALID_CLIENT_ID)

    const state = locationUrl.searchParams.get(STATE)
    expect(state).toBe(reqParams.state)
  })
})

describe('Authorize endpoint', async () => {
  it('should return error if client_id is missing', async () => {
    const reqParams = {
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
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
    const locationUrl = new URL(response.headers.location)

    const errorDescription = locationUrl.searchParams.get(ERROR_DESCRIPTION)
    expect(errorDescription).toBe(ERR_MSG_INVALID_CLIENT_ID)

    const state = locationUrl.searchParams.get(STATE)
    expect(state).toBe(reqParams.state)
  })
})

describe('Authorize endpoint', async () => {
  it('should return error if redirect uri is invalid', async () => {
    const reqParams = {
      client_id: CLIENT_ID,
      redirect_uri: 'http://example.com/',
      response_type: 'id_token',
      scope: 'opendid',
      state: TestState.STATE,
      nonce: '',
    }
    const urlWithParams = addQueryParamsToUrl(authorizeUrl, reqParams)
    const response = await axios.get(urlWithParams.toString(), {
      maxRedirects: 0,
      validateStatus: () => true,
    })

    expect(response.status).toBe(302)
    const locationUrl = new URL(response.headers.location)

    const errorDescription = locationUrl.searchParams.get(ERROR_DESCRIPTION)
    expect(errorDescription).toBe(ERR_MSG_INVALID_REDIRECT_URI)

    const state = locationUrl.searchParams.get(STATE)
    expect(state).toBe(reqParams.state)
  })
})

describe('Authorize endpoint', async () => {
  it('should return error if response type is missing', async () => {
    const reqParams = {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'opendid',
      state: TestState.STATE,
      nonce: TestState.NONCE,
    }
    const urlWithParams = addQueryParamsToUrl(authorizeUrl, reqParams)
    const response = await axios.get(urlWithParams.toString(), {
      maxRedirects: 0,
      validateStatus: () => true,
    })

    expect(response.status).toBe(302)
    const locationUrl = new URL(response.headers.location)

    const errorDescription = locationUrl.searchParams.get(ERROR_DESCRIPTION)
    expect(errorDescription).toBe(ERR_MSG_INVALID_RESPONSE_TYPE)

    const state = locationUrl.searchParams.get(STATE)
    expect(state).toBe(reqParams.state)
  })
})

describe('Authorize endpoint', async () => {
  it('should return error if nonce is not given for implicit flow', async () => {
    const reqParams = {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'id_token', //implicit flow
      scope: 'opendid',
      state: TestState.STATE,
    }
    const urlWithParams = addQueryParamsToUrl(authorizeUrl, reqParams)
    const response = await axios.get(urlWithParams.toString(), {
      maxRedirects: 0,
      validateStatus: () => true,
    })

    expect(response.status).toBe(302)
    const locationUrl = new URL(response.headers.location)

    const errorDescription = locationUrl.searchParams.get(ERROR_DESCRIPTION)
    expect(errorDescription).toBe(ERR_MSG_INVALID_NONCE)

    const state = locationUrl.searchParams.get(STATE)
    expect(state).toBe(reqParams.state)
  })
})
