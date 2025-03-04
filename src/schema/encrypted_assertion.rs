use crate::schema::Assertion;
use base64::Engine as _;
use openssl::pkey::Private;
use openssl::symm::Crypter;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::{Deserialize, Deserializer};
use std::io::Cursor;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedAssertion {
    pub encrypted_data: EncryptedData,
}

impl<'de> Deserialize<'de> for EncryptedAssertion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            #[serde(rename = "EncryptedData")]
            encrypted_data: Option<EncryptedData>,

            // Alternative field name with namespace prefix
            #[serde(rename = "xenc:EncryptedData")]
            xenc_encrypted_data: Option<EncryptedData>,
        }

        let helper = Helper::deserialize(deserializer)?;

        // Use either the namespaced or non-namespaced version
        let encrypted_data = helper
            .encrypted_data
            .or(helper.xenc_encrypted_data)
            .ok_or_else(|| serde::de::Error::custom("Missing EncryptedData"))?;

        Ok(EncryptedAssertion { encrypted_data })
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedData {
    #[serde(rename = "@Type")]
    pub type_attr: Option<String>,
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: EncryptionMethod,
    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,
    #[serde(rename = "CipherData")]
    pub cipher_data: CipherData,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptionMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyInfo {
    pub encrypted_key: EncryptedKey,
}

impl<'de> Deserialize<'de> for KeyInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            #[serde(rename = "EncryptedKey")]
            encrypted_key: Option<EncryptedKey>,

            // Alternative field name with namespace prefix
            #[serde(rename = "xenc:EncryptedKey")]
            xenc_encrypted_key: Option<EncryptedKey>,
        }

        let helper = Helper::deserialize(deserializer)?;

        // Use either the namespaced or non-namespaced version
        let encrypted_key = helper
            .encrypted_key
            .or(helper.xenc_encrypted_key)
            .ok_or_else(|| serde::de::Error::custom("Missing EncryptedKey"))?;

        Ok(KeyInfo { encrypted_key })
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedKey {
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: EncryptionMethod,
    #[serde(rename = "CipherData")]
    pub cipher_data: CipherData,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CipherData {
    #[serde(rename = "CipherValue")]
    pub cipher_value: String,
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Failed to decrypt assertion: {0}")]
    DecryptionFailed(String),

    #[error("Unsupported encryption algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),

    #[error("XML parsing error: {0}")]
    XmlParseError(String),
}

impl EncryptedAssertion {
    pub fn decrypt(
        &self,
        private_key: &openssl::pkey::PKey<Private>,
    ) -> Result<Assertion, DecryptionError> {
        // 1. Decrypt the encrypted key with the private key
        let encrypted_key_value = &self
            .encrypted_data
            .key_info
            .encrypted_key
            .cipher_data
            .cipher_value;
        let encrypted_key_bytes =
            base64::engine::general_purpose::STANDARD.decode(encrypted_key_value)?;

        // Get the key encryption algorithm
        let key_enc_algorithm = &self
            .encrypted_data
            .key_info
            .encrypted_key
            .encryption_method
            .algorithm;

        // Decrypt the session key
        let session_key = match key_enc_algorithm.as_str() {
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => {
                let rsa = private_key.rsa()?;
                let mut decrypted = vec![0; rsa.size() as usize];
                let len = rsa.private_decrypt(
                    &encrypted_key_bytes,
                    &mut decrypted,
                    openssl::rsa::Padding::PKCS1_OAEP,
                )?;
                decrypted[..len].to_vec()
            }
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5" => {
                let rsa = private_key.rsa()?;
                let mut decrypted = vec![0; rsa.size() as usize];
                let len = rsa.private_decrypt(
                    &encrypted_key_bytes,
                    &mut decrypted,
                    openssl::rsa::Padding::PKCS1,
                )?;
                decrypted[..len].to_vec()
            }
            _ => {
                return Err(DecryptionError::UnsupportedAlgorithm(
                    key_enc_algorithm.clone(),
                ))
            }
        };

        // 2. Decrypt the assertion with the session key
        let encrypted_data_value = &self.encrypted_data.cipher_data.cipher_value;
        let encrypted_data_bytes =
            base64::engine::general_purpose::STANDARD.decode(encrypted_data_value)?;

        // Get the data encryption algorithm
        let data_enc_algorithm = &self.encrypted_data.encryption_method.algorithm;

        // Decrypt the assertion XML
        let decrypted_xml = match data_enc_algorithm.as_str() {
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => decrypt_aes(
                &encrypted_data_bytes,
                &session_key,
                openssl::symm::Cipher::aes_128_cbc(),
            )?,
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => decrypt_aes(
                &encrypted_data_bytes,
                &session_key,
                openssl::symm::Cipher::aes_192_cbc(),
            )?,
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => decrypt_aes(
                &encrypted_data_bytes,
                &session_key,
                openssl::symm::Cipher::aes_256_cbc(),
            )?,
            _ => {
                return Err(DecryptionError::UnsupportedAlgorithm(
                    data_enc_algorithm.clone(),
                ))
            }
        };

        // 3. Parse the decrypted XML into an Assertion
        let decrypted_xml_str = String::from_utf8(decrypted_xml)
            .map_err(|e| DecryptionError::XmlParseError(e.to_string()))?;

        // Parse the XML into an Assertion
        decrypted_xml_str
            .parse::<Assertion>()
            .map_err(|e| DecryptionError::XmlParseError(e.to_string()))
    }
}

fn decrypt_aes(
    encrypted_data: &[u8],
    key: &[u8],
    cipher: openssl::symm::Cipher,
) -> Result<Vec<u8>, DecryptionError> {
    // AES-CBC requires an IV (first 16 bytes of the encrypted data)
    if encrypted_data.len() <= 16 {
        return Err(DecryptionError::DecryptionFailed(
            "Encrypted data too short".to_string(),
        ));
    }

    let iv = &encrypted_data[0..16];
    let ciphertext = &encrypted_data[16..];

    // Make sure the key is the correct length for the cipher
    let key_len = cipher.key_len();

    // Create a key of the exact required length
    let key_to_use = if key.len() == key_len {
        key.to_vec()
    } else if key.len() > key_len {
        key[..key_len].to_vec()
    } else {
        // Key is too short, this is likely the issue
        let mut extended_key = key.to_vec();
        extended_key.resize(key_len, 0);
        extended_key
    };

    let mut decrypter = Crypter::new(cipher, openssl::symm::Mode::Decrypt, &key_to_use, Some(iv))?;
    decrypter.pad(false);

    let mut decrypted = vec![0; ciphertext.len() + cipher.block_size()];
    let count = decrypter.update(ciphertext, &mut decrypted)?;
    let rest = decrypter.finalize(&mut decrypted[count..])?;

    decrypted.truncate(count + rest);

    Ok(decrypted)
}

impl FromStr for EncryptedAssertion {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl TryFrom<EncryptedAssertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EncryptedAssertion) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptedAssertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedAssertion) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let root = BytesStart::new("saml2:EncryptedAssertion");
        writer.write_event(Event::Start(root))?;

        // Convert EncryptedData to Event and write it
        let encrypted_data_event: Event<'_> = (&value.encrypted_data).try_into()?;
        writer.write_event(encrypted_data_event)?;

        writer.write_event(Event::End(BytesEnd::new("saml2:EncryptedAssertion")))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

// Implement TryFrom for EncryptedData
impl TryFrom<&EncryptedData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let mut root = BytesStart::new("xenc:EncryptedData");
        root.push_attribute(("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#"));

        if let Some(type_attr) = &value.type_attr {
            root.push_attribute(("Type", type_attr.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        // Write EncryptionMethod
        let encryption_method_event: Event<'_> = (&value.encryption_method).try_into()?;
        writer.write_event(encryption_method_event)?;

        // Write KeyInfo
        let key_info_event: Event<'_> = (&value.key_info).try_into()?;
        writer.write_event(key_info_event)?;

        // Write CipherData
        let cipher_data_event: Event<'_> = (&value.cipher_data).try_into()?;
        writer.write_event(cipher_data_event)?;

        writer.write_event(Event::End(BytesEnd::new("xenc:EncryptedData")))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

// Implement TryFrom for EncryptionMethod
impl TryFrom<&EncryptionMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptionMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let mut root = BytesStart::new("xenc:EncryptionMethod");
        root.push_attribute(("Algorithm", value.algorithm.as_ref()));

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::new("xenc:EncryptionMethod")))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

// Implement TryFrom for KeyInfo
impl TryFrom<&KeyInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &KeyInfo) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let mut root = BytesStart::new("ds:KeyInfo");
        root.push_attribute(("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));

        writer.write_event(Event::Start(root))?;

        // Write EncryptedKey
        let encrypted_key_event: Event<'_> = (&value.encrypted_key).try_into()?;
        writer.write_event(encrypted_key_event)?;

        writer.write_event(Event::End(BytesEnd::new("ds:KeyInfo")))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

// Implement TryFrom for EncryptedKey
impl TryFrom<&EncryptedKey> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedKey) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let root = BytesStart::new("xenc:EncryptedKey");
        writer.write_event(Event::Start(root))?;

        // Write EncryptionMethod
        let encryption_method_event: Event<'_> = (&value.encryption_method).try_into()?;
        writer.write_event(encryption_method_event)?;

        // Write CipherData
        let cipher_data_event: Event<'_> = (&value.cipher_data).try_into()?;
        writer.write_event(cipher_data_event)?;

        writer.write_event(Event::End(BytesEnd::new("xenc:EncryptedKey")))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

// Implement TryFrom for CipherData
impl TryFrom<&CipherData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &CipherData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let root = BytesStart::new("xenc:CipherData");
        writer.write_event(Event::Start(root))?;

        // Write CipherValue
        let cipher_value = BytesStart::new("xenc:CipherValue");
        writer.write_event(Event::Start(cipher_value))?;
        writer.write_event(Event::Text(BytesText::from_escaped(&value.cipher_value)))?;
        writer.write_event(Event::End(BytesEnd::new("xenc:CipherValue")))?;

        writer.write_event(Event::End(BytesEnd::new("xenc:CipherData")))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
