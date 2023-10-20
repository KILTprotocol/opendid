use serde::{Deserialize, Serialize};

use crate::serialize::prefixed_hex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    #[serde(rename = "ciphertext")]
    #[serde(with = "prefixed_hex")]
    pub cipher_text: Vec<u8>,
    #[serde(with = "prefixed_hex")]
    pub nonce: Vec<u8>,
    #[serde(rename = "receiverKeyUri")]
    pub receiver_key_uri: String,
    #[serde(rename = "senderKeyUri")]
    pub sender_key_uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageBody<T> {
    #[serde(rename = "type")]
    pub type_: String,
    pub content: T,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<T> {
    pub body: MessageBody<T>,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    pub sender: String,
    pub receiver: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "inReplyTo")]
    pub in_reply_to: Option<String>,
    pub references: Option<Vec<String>>,
}
