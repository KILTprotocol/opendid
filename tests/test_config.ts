import { ICredential } from '@kiltprotocol/sdk-js'


// `client_id` and `redirect_uri` allowed by the OpenDID service and set in the `config.yaml` file.
export const CLIENT_ID = 'example-client'
export const REDIRECT_URI = 'http://localhost:1606/callback.html'
export const CLIENT_SECRET = 'insecure_client_secret'

// The credential used for authentication the test user. It must be issued by an attester accepted
// by the OpenDID Service (SocialKYC by default).
export const CREDENTIAL: ICredential = {
  claim: {
    cTypeHash: '0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac',
    contents: {
      Email: 'abdul@kilt.io',
    },
    owner: 'did:kilt:4oEd4CUWtpnLTVvD5PEwiLRij1gsBjkKRLmZDKiB8Gj7b6WL',
  },
  claimHashes: [
    '0x5c04f3dd627c9f70f82c2f771a64a8dcae65267597cdc779f534d8b6b846cf53',
    '0x971ac804702376a1149cc3c075a0974f077d45dfe5df2d5c339d04b67b1ddd32',
  ],
  claimNonceMap: {
    '0x07e62e38d553baffb868001bee6a4a2b6aa918d5dd4ae8b6ce7d15fc08713ae9': '3a237490-0010-4834-b435-6a7d809d6fc3',
    '0xd2d91e4a79ff4b2d13be0f6badaddcd934fa7f40f716f54d93527e85732b7730': '1f757394-f002-48b0-a11d-93868328f509',
  },
  delegationId: null,
  legitimations: [],
  rootHash: '0x627b79e3008e7f9a1c6ffb4c7f494fd75299c263f0dc7f0c4326a4a9dd24e754',
}

// Ctype hash of the ctype accepted by the OpenDID service.
export const REQUIRED_CTYPE_HASH = '0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac'

// DID URL of the authrorization key of the test user DID.
export const DID_AUTH_KEY_URL =
  'did:kilt:4oEd4CUWtpnLTVvD5PEwiLRij1gsBjkKRLmZDKiB8Gj7b6WL#0x0b174e48f077e78985f985838b43fdccf6538345030603aafd7a53eaf83b66fb'
// DID URL of the key agreement key of the test user DID.
export const DID_KEY_AGREEMENT_URL =
  'did:kilt:4oEd4CUWtpnLTVvD5PEwiLRij1gsBjkKRLmZDKiB8Gj7b6WL#0xe3c90f033833b48d6ee216ea25b0ac05c9d5fe5c0b602440b167d94d46747d01'
