
export interface EncryptedMessage {
  receiverKeyUri: string
  senderKeyUri: string
  ciphertext: string
  nonce: string
  receivedAt?: number
}

export interface Requirments {
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
