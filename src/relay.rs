use crate::{
    bundle::BundleHash,
    jsonrpc::{JsonRpcError, Request, Response},
};
use ethers::core::{
    types::{H256, U64},
    utils::keccak256,
};
use ethers::signers::Signer;
use reqwest::{Client, Error as ReqwestError};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use url::Url;
use std::collections::HashSet;

/// A Flashbots relay client.
///
/// The client automatically signs every request and sets the Flashbots
/// authorization header appropriately with the given signer.
///
/// **Note**: You probably do not want to use this directly, unless
/// you want to interact directly with the Relay. Most users should use
/// [`FlashbotsMiddleware`](crate::FlashbotsMiddleware) instead.
#[derive(Debug)]
pub struct Relay<S> {
    id: AtomicU64,
    client: Client,
    url: Url,
    signer: Option<S>,
}

/// Errors for relay requests.
#[derive(Error, Debug)]
pub enum RelayError<S: Signer> {
    /// The request failed.
    #[error(transparent)]
    RequestError(#[from] ReqwestError),
    /// The request could not be parsed.
    #[error(transparent)]
    JsonRpcError(#[from] JsonRpcError),
    /// The request parameters were invalid.
    #[error("Client error: {text}")]
    ClientError { text: String },
    /// The request could not be serialized.
    #[error(transparent)]
    RequestSerdeJson(#[from] serde_json::Error),
    /// The request could not be signed.
    #[error(transparent)]
    SignerError(#[from(S::Error)] S::Error),
    /// The response could not be deserialized.
    #[error("Deserialization error: {err}. Response: {text}")]
    ResponseSerdeJson {
        err: serde_json::Error,
        text: String,
    },
}

impl<S: Signer> Relay<S> {
    /// Initializes a new relay client.
    pub fn new(url: impl Into<Url>, signer: Option<S>) -> Self {
        Self {
            id: AtomicU64::new(0),
            client: Client::new(),
            url: url.into(),
            signer,
        }
    }

    /// Sends a request with the provided method to the relay, with the
    /// parameters serialized as JSON.
    pub async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, RelayError<S>> {
        let next_id = self.id.load(Ordering::SeqCst) + 1;
        self.id.store(next_id, Ordering::SeqCst);

        let payload = Request::new(next_id, method, params);

        let mut req = self.client.post(self.url.as_ref());

        if let Some(signer) = &self.signer {
            let signature = signer
                .sign_message(format!(
                    "0x{:x}",
                    H256::from(keccak256(
                        serde_json::to_string(&payload)
                            .map_err(RelayError::RequestSerdeJson)?
                            .as_bytes()
                    ))
                ))
                .await
                .map_err(RelayError::SignerError)?;

            req = req.header(
                "X-Flashbots-Signature",
                format!("{:?}:0x{}", signer.address(), signature),
            );
        }

        let res = req.json(&payload).send().await?;
        let status = res.error_for_status_ref();

        match status {
            Err(err) => {
                let text = res.text().await?;
                let status_code = err.status().unwrap();
                if status_code.is_client_error() {
                    // Client error (400-499)
                    Err(RelayError::ClientError { text })
                } else {
                    // Internal server error (500-599)
                    Err(RelayError::RequestError(err))
                }
            }
            Ok(_) => {
               let mut text = res.text().await?;
               
                if method == "eth_sendBundle"
                { 
                    //If it this this builder then we check cause they send double result
                    if self.url == Url::parse("https://rpc.lightspeedbuilder.info").unwrap()  
                    {
                        
                        // Split the input into individual JSON strings
                        let split_json: Vec<&str> = text.split('\n').collect();

                        // Create a HashSet to store unique JSON strings
                        let mut unique_json_set: HashSet<&str> = HashSet::new();

                        // Filter out duplicates and store unique JSON strings in the set
                        for json_str in split_json {
                            unique_json_set.insert(json_str);
                            
                        }
                        // Convert the unique JSON strings set back into a vector
                        let unique_json_vec: Vec<&str> = unique_json_set.into_iter().collect();

                        // Join the unique JSON strings back into a single string
                        let unique_json_string = unique_json_vec.join("\n");

                        text = unique_json_string;
                        
                    }

                    let parsed_response: serde_json::Value = serde_json::from_str(&text).expect("Failed to parse JSON response");
                   
                    if self.url == Url::parse("https://builder0x69.io").unwrap() 
                    || self.url == Url::parse("https://rsync-builder.xyz").unwrap()  
                    || self.url == Url::parse("https://rpc.lokibuilder.xyz").unwrap()  
                    {
                         // Check if the "result" field is null
                        if let Some(result) = parsed_response.get("result")
                        {
                            if result.is_null() ||  result == "nil"
                            {   
                                //We put a random hash considering the relay does not provide a bundle hash in his result
                                text = r#"{"id":1,"jsonrpc":"2.0","result":{"bundleHash":"0xdabb05c0936748614a1b114fdc302d8ec46bb2f8b998994f901ad255019c497f"}}"#.to_string();
                            }
                        }
                    }
                    //If it is this builder we check cause it does not have any id
                    else if self.url == Url::parse("https://rpc.payload.de").unwrap()  
                    {
                        if parsed_response.get("id").is_none() 
                        {
                            text = r#"{"id":1,"jsonrpc":"2.0","result":{"bundleHash":"0xdabb05c0936748614a1b114fdc302d8ec46bb2f8b998994f901ad255019c497f"}}"#.to_string();
                        }
                    }
                     
                }
                
                let res: Response<R> = serde_json::from_str(&text)
                    .map_err(|err| RelayError::ResponseSerdeJson { err, text })?;

                Ok(res.data.into_result()?)
            }
        }
    }
}

impl<S: Signer + Clone> Clone for Relay<S> {
    fn clone(&self) -> Self {
        Self {
            id: AtomicU64::new(0),
            client: self.client.clone(),
            url: self.url.clone(),
            signer: self.signer.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendBundleResponse {
    pub(crate) bundle_hash: BundleHash,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetBundleStatsParams {
    pub(crate) bundle_hash: BundleHash,
    pub(crate) block_number: U64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetUserStatsParams {
    pub(crate) block_number: U64,
}
