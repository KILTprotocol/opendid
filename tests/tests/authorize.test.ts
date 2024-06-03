import 'dotenv/config'
import axios from 'axios'
import { addQueryParamsToUrl } from './utils'

let opendidEndpoint = process.env.OPENDID_URL
let authorizeUrl = new URL("api/v1/authorize", opendidEndpoint)

let req_params = {
  client_id: "example-client",
  redirect_uri: "http://localhost:1606/callback.html",
  response_type: "code",
  scope: "opendid",
  state: "state-test-123",
  nonce: "nonce-test-123",
}

describe("authorize", () => {
  test("should support Authorization Code Flow", async () => {

    let urlWithParams = addQueryParamsToUrl(authorizeUrl, req_params)
    // Don't redirect, and don't throw on status 302.
    let a = await axios.get(urlWithParams.toString(), { maxRedirects: 0, validateStatus: (status) => { return status == 302 } });
    expect(a.headers.location).toEqual("/")
    expect(a.data).toEqual("")
  })

  test("should support Implicit Flow", async () => {
    req_params.response_type = "id_token"
    let urlWithParams = addQueryParamsToUrl(authorizeUrl, req_params)
    // Don't redirect, and don't throw on status 302.
    let a = await axios.get(urlWithParams.toString(), { maxRedirects: 0, validateStatus: (status) => { return status == 302 } });
    expect(a.headers.location).toEqual("/")
    expect(a.data).toEqual("")
  })
})
