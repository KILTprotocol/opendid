import * as Kilt from '@kiltprotocol/sdk-js'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import { fromHex, toHex } from '@smithy/util-hex-encoding'
import { AxiosResponse } from 'axios'
import Cookie from 'cookie'
import { assert } from 'vitest'

export class TestState {
  static STATE = 'test-state-value-123'
  static NONCE = 'test-nonce-value-123'
  private lightDIDKeyAgreement: Kilt.KiltEncryptionKeypair
  private lightDid: Kilt.DidDocument
  private cookie: string
  private openDidKeyAgreement?: Kilt.ResolvedDidKey
  private code?: string

  public constructor() {
    const mnemonic = mnemonicGenerate()
    const authentication = Kilt.Utils.Crypto.makeKeypairFromUri(mnemonic)
    const keyAgreement = Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(
      Kilt.Utils.Crypto.mnemonicToMiniSecret(mnemonic),
    )
    this.lightDIDKeyAgreement = keyAgreement
    this.lightDid = Kilt.Did.createLightDidDocument({
      authentication: [authentication],
      keyAgreement: [keyAgreement],
    })
    this.cookie = ''
    this.openDidKeyAgreement = undefined
  }

  /**
   * Sets the key agreement key used by the OpenDID Service.
   */
  public setOpenDidKeyAgreement(openDidKeyAgreement: Kilt.ResolvedDidKey) {
    this.openDidKeyAgreement = openDidKeyAgreement
  }

  /**
   * Gets the key agreement key used by the OpenDID Service.
   */
  public getOpenDidKeyAgreement(): Kilt.ResolvedDidKey {
    if (!this.openDidKeyAgreement) {
      throw new Error('openDidKeyAgreement is not set')
    }
    return this.openDidKeyAgreement!
  }

  /**
   * Retrieves the set `opendid`  cookie from a request and stores it
   * in the `TestState`
   **/
  public setCookie(response: AxiosResponse) {
    const cookie = response.headers['set-cookie']!.pop()!
    const parsedCookie = Cookie.parse(cookie)
    this.cookie = 'opendid=' + parsedCookie['opendid']
  }

  /**
   * Returns the stored `opendid` cookie.
   */
  public getCookie(): string {
    return this.cookie
  }

  /**
   * Returns the light DID Document used for Deffie Hellmann.
   */
  public getLightDidDocument(): Kilt.DidDocument {
    return this.lightDid
  }

  /**
   * Sets the Authorization Code returned from `POST /credentials` for Authorization Code Flow
   */
  public setAuthCode(code: string) {
    this.code = code
  }

  /**
   * Returns Authorization Code returned from `POST /credentials` for Authorization Code Flow
   */
  public getAuthCode(): string {
    assert(this.code !== undefined, 'code is not set!')
    return this.code
  }

  /**
   * Encrypt data using the secret keyAgreement of the Light DID  and public key of OpenDID Service.
   */
  public encrypt(input: Uint8Array): { box: string; nonce: string } {
    assert(this.openDidKeyAgreement !== undefined, 'openDidKeyAgreement is not set!')
    const encrypted = Kilt.Utils.Crypto.encryptAsymmetric(
      input,
      this.openDidKeyAgreement.publicKey,
      this.lightDIDKeyAgreement.secretKey,
    )

    return { box: '0x' + toHex(encrypted.box), nonce: '0x' + toHex(encrypted.nonce) }
  }

  /**
   * Decrypt data using the secret keyAgreement of the Light DID  and public key of OpenDID Service.
   */
  public decrypt(box: string, nonce: string): string {
    assert(this.openDidKeyAgreement !== undefined, 'openDidKeyAgreement is not set!')
    const input = {
      box: fromHex(box.replace('0x', '')),
      nonce: fromHex(nonce.replace('0x', '')),
    }

    const decrypted = Kilt.Utils.Crypto.decryptAsymmetric(
      input,
      this.openDidKeyAgreement!.publicKey,
      this.lightDIDKeyAgreement.secretKey,
    )
    if (decrypted === false) {
      throw new Error('decryption failed')
    } else {
      return new TextDecoder().decode(decrypted)
    }
  }
}
