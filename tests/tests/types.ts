export interface Requirements {
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
