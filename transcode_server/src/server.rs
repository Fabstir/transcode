/*
 * server.rs
 *
 * This file contains code for transcoding a video using ffmpeg.
 * Upload a video in any format that ffmpeg can read
 * The video is then transcoded to multiple formats specified in `video_formats.json` file
 * to different codecs, bitrates, resolutions and son on.
 * These transcoded videos are uploaded to decentralised SIA Storage via S5.
 *
 * Author: Jules Lai
 * Date: 28 May 2023
 */

mod s5;

mod encrypt_file;

mod transcode_video;
use transcode_video::{
    base64url_to_bytes, bytes_to_base64url, download_and_concat_files, download_video,
    transcode_video,
};

use tonic::{transport::Server, Request, Response, Status};
use warp::Filter;

use async_trait::async_trait;

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use transcode::{
    transcode_service_server::{TranscodeService, TranscodeServiceServer},
    GetTranscodedRequest, GetTranscodedResponse, TranscodeRequest, TranscodeResponse,
};

mod encrypted_cid;
use crate::encrypt_file::decrypt_file_xchacha20;

use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use std::fs::read_to_string;

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use chrono::Utc;
use uuid::{Uuid, Version};

use base64;
use std::convert::TryInto;

use dotenv::{dotenv, var};

static TRANSCODED: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn get_file_size(file_path: String) -> std::io::Result<u64> {
    let metadata = fs::metadata(file_path)?;
    Ok(metadata.len())
}

const CID_TYPE_ENCRYPTED_SIZE: usize = 1;
const ENCRYPTION_ALGORITHM_SIZE: usize = 1;
const CHUNK_SIZE_AS_POWEROF2_SIZE: usize = 1;

const KEY_SIZE: usize = 32;
const PADDING_SIZE: usize = 4;
const ORIGINAL_CID_SIZE: usize = 37;

/**
 * Extracts the encryption key from an encrypted CID.
 * @param encrypted_cid - The encrypted CID to get the key from.
 * @returns The encryption key from the CID.
 */
pub fn get_key_from_encrypted_cid(encrypted_cid: &str) -> String {
    let extension_index = encrypted_cid.rfind(".");

    let mut cid_without_extension = match extension_index {
        Some(index) => &encrypted_cid[..index],
        None => encrypted_cid,
    };

    println!(
        "get_key_from_encrypted_cid: encrypted_cid = {}",
        encrypted_cid
    );
    println!(
        "get_key_from_encrypted_cid: cid_without_extension = {}",
        cid_without_extension
    );

    cid_without_extension = &cid_without_extension[1..];
    let cid_bytes = base64url_to_bytes(cid_without_extension);
    let start_index = cid_bytes.len() - KEY_SIZE - PADDING_SIZE - ORIGINAL_CID_SIZE;
    let end_index = cid_bytes.len() - PADDING_SIZE - ORIGINAL_CID_SIZE;
    let selected_bytes = &cid_bytes[start_index..end_index];

    let key = bytes_to_base64url(selected_bytes);
    println!("get_key_from_encrypted_cid: key = {}", key);

    return key;
}

/// Calculates the SHA-256 hash of the given `blob` and encrypts it using the
/// `key` using AES-256-CBC encryption. The resulting encrypted hash is then
/// base64-encoded and URL-safe. Returns the resulting hash as a `String`.
///
/// # Arguments
///
/// * `blob` - The blob to hash and encrypt.
/// * `key` - The encryption key to use.
///
pub fn get_base64_url_encrypted_blob_hash(encrypted_cid: &str) -> Option<String> {
    let encrypted_cid = &encrypted_cid[1..];
    let cid_bytes = base64url_to_bytes(encrypted_cid);

    // Calculate the size of encryptedBlobHash
    let encrypted_blob_hash_size = cid_bytes.len()
        - CID_TYPE_ENCRYPTED_SIZE
        - ENCRYPTION_ALGORITHM_SIZE
        - CHUNK_SIZE_AS_POWEROF2_SIZE
        - KEY_SIZE
        - PADDING_SIZE
        - ORIGINAL_CID_SIZE;

    println!("encrypted_blob_hash_size: {}", encrypted_blob_hash_size);

    let encrypted_blob_hash = &cid_bytes[3..(3 + encrypted_blob_hash_size)];

    let base64_url = bytes_to_base64url(encrypted_blob_hash);

    Some(base64_url)
}

/// Generates a random filename with the given `prefix` and `extension`.
/// The filename is guaranteed to be unique and not already exist in the
/// current directory. Returns the resulting filename as a `String`.
///
/// # Arguments
///
/// * `prefix` - The prefix to use for the filename.
/// * `extension` - The extension to use for the filename.
///
fn generate_random_filename() -> String {
    let uuid = Uuid::new_v4();
    let timestamp = Utc::now().timestamp_nanos();
    format!("{}_{}", uuid, timestamp)
}

/// Receives transcoding tasks from the `transcode_task_sender` channel and
/// processes them. For each task, it reads the input file from disk, transcodes
/// it using the specified `transcoder`, and writes the output file to disk.
/// If an error occurs during any of these steps, it logs the error and continues
/// processing the next task. Once all tasks have been processed, it sends a
/// message to the `transcode_done_sender` channel to signal that it has finished.
///
/// # Arguments
///
/// * `transcode_task_sender` - The sender channel for transcoding tasks.
/// * `transcode_done_sender` - The sender channel for the "transcoding done" message.
/// * `transcoder` - The transcoder to use for transcoding the input files.
///
async fn transcode_task_receiver(receiver: Arc<Mutex<mpsc::Receiver<(String, bool, bool)>>>) {
    while let Some((orig_source_cid, is_gpu, is_encrypt)) = receiver.lock().await.recv().await {
        let source_cid = Path::new(&orig_source_cid)
            .with_extension("")
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid source CID")
            })
            .unwrap()
            .to_string();

        // First, we download the video and save it locally
        let portal_url = if is_encrypt {
            var("PORTAL_ENCRYPT_URL").unwrap()
        } else {
            var("PORTAL_URL").unwrap()
        };

        //        let test_source_cid: &str = "urqYSH2i-rVUD1F-aUZDJ1Oh8BrzqsXhJPJ58QXDxxSQJD0isRsz0lC2jm-4uZ_Pi93mmoxW3ZYLzcJ55UnQxvuCeCa0AAAAAJh8GPLdBfbDGEp11IM4f7tTgklU60suWg2nMlScJJ9ogDcv5Dw";
        println!("source_cid: {}", source_cid);
        println!("portal_url: {}", portal_url);

        let file_path;

        if (is_encrypt) {
            println!("Encrypted CID: {}", source_cid);
            // Extract the BASE64_URL_ENCRYPTED_BLOB_HASH from encrypted CID
            let base64_url_encrypted_blob_hash = get_base64_url_encrypted_blob_hash(&source_cid)
                .expect("Failed to get base64 URL encrypted blob hash");

            // GET https://s5.cx/api/locations/BASE64_URL_ENCRYPTED_BLOB_HASH?types=5,3 to get download urls for your encrypted file
            let url = format!(
                "{}{}{}?types=5,3",
                portal_url, "/api/locations/", base64_url_encrypted_blob_hash
            );
            println!("Downloading and then transcoding video from URL: {}", &url);

            let file_encrypted_metadata = match download_video(&url).await {
                Ok(file_path) => file_path,
                Err(e) => {
                    eprintln!(
                        "Failed to download encrypted video from URL {}: {}",
                        &url, e
                    );
                    continue;
                }
            };

            let encrypted_metadata = match std::fs::read_to_string(&file_encrypted_metadata) {
                Ok(contents) => contents,
                Err(e) => {
                    eprintln!(
                        "Failed to read encrypted metadata from file {}: {}",
                        &file_encrypted_metadata, e
                    );
                    continue;
                }
            };

            let path_to_file = var("PATH_TO_FILE").unwrap();
            let file_path_encrypted = format!("{}{}", path_to_file, generate_random_filename());

            // get download urls for your encrypted file
            // and then just download the encrypted file using any http download library
            match download_and_concat_files(encrypted_metadata, file_path_encrypted.clone()).await {
                Ok(()) => println!("Download and concatenation succeeded"),
                Err(e) => eprintln!("Download and concatenation failed: {}", e),
            }

            file_path = format!("{}_ue", file_path_encrypted);

            let file_encrypted_size = get_file_size(file_path_encrypted.clone()).unwrap();
            println!("file_path_encrypted: {}", file_path_encrypted);
            println!("file_encrypted_size: {}", file_encrypted_size);

            // last chunk index is floor(encrypted file size / (262144 + 16)) for the default chunk size
            // iirc padding is 0 in your case
            let last_index_size =
                (file_encrypted_size as f64 / (262144 + 16) as f64).floor() as u32;

            let key = get_key_from_encrypted_cid(&source_cid);
            let key_bytes = base64url_to_bytes(&key);
            //let key_bytes = vec![0; 32];

            println!("file_path: {}", file_path);
            println!("key: {}", key);
            println!("key_bytes: {:?}", key_bytes);
            println!("last_index_size: {}", last_index_size);

            // decrypt_file_xchacha20 from vup
            match decrypt_file_xchacha20(
                file_path_encrypted,
                file_path.clone(),
                key_bytes,
                0,
                last_index_size,
            ) {
                Ok(bytes) => {
                    println!("Decryption succeeded");
                }
                Err(error) => {
                    eprintln!("Decryption error: {:?}", error);
                }
            }
        } else {
            let url = format!("{}{}{}", portal_url, "/s5/blob/", source_cid);

            // First, we download the video and save it locally
            file_path = match download_video(&url).await {
                Ok(file_path) => file_path,
                Err(e) => {
                    eprintln!("Failed to download video from URL {}: {}", &url, e);
                    continue;
                }
            };
        }

        // Read the video formats from the JSON file
        let video_formats_json = read_to_string("./settings/video_formats.json")
            .expect("Failed to read video format file");
        let video_formats: Vec<Value> =
            serde_json::from_str(&video_formats_json).expect("Failed to parse video formats");

        // Then, we transcode the downloaded video with each video format
        let mut transcoded_formats = Vec::new();
        for video_format in video_formats {
            let video_format = serde_json::to_string(&video_format)
                .expect("Failed to convert JSON value to string");
            let transcode_result =
                transcode_video(&file_path, &video_format, is_gpu, is_encrypt).await;

            // Handle potential errors
            if let Err(e) = &transcode_result {
                eprintln!("Failed to transcode {}: {}", &file_path, e);
            } else {
                // Unwrap the successful result
                let transcode_response = transcode_result.unwrap();
                let response = transcode_response.into_inner();

                println!(
                    "Response: status_code: {}, message: {}, cid: {}",
                    response.status_code, response.message, response.cid
                );

                let mut video_format: Value =
                    serde_json::from_str(&video_format).expect("Failed to parse video format");
                video_format["cid"] = json!(response.cid);

                transcoded_formats.push(video_format.clone());
            }
        }

        let transcoded_json = serde_json::to_string(&transcoded_formats)
            .expect("Failed to convert transcoded formats to JSON");

        let mut transcoded = TRANSCODED.lock().await;
        transcoded.insert(source_cid.clone(), transcoded_json);
    }
}

// The gRPC service implementation
#[derive(Debug, Clone)]
struct TranscodeServiceHandler {
    transcode_task_sender: Option<Arc<Mutex<mpsc::Sender<(String, bool, bool)>>>>,
}

#[async_trait]
impl TranscodeService for TranscodeServiceHandler {
    async fn transcode(
        &self,
        request: Request<TranscodeRequest>,
    ) -> Result<Response<TranscodeResponse>, Status> {
        let source_cid = request.get_ref().source_cid.clone();
        println!("Received source_cid: {}", source_cid);

        let is_gpu = request.get_ref().is_gpu;
        println!("Received is_gpu: {}", is_gpu);

        let is_encrypt = request.get_ref().is_encrypt;
        println!("Received is_encrypt: {}", is_encrypt);

        println!(
            "transcode_task_sender is None: {}",
            self.transcode_task_sender.is_none()
        );

        // Send the transcoding task to the transcoding task receiver
        if let Some(ref sender) = self.transcode_task_sender {
            let sender = sender.lock().await.clone();

            if let Err(e) = sender.send((source_cid.clone(), is_gpu, is_encrypt)).await {
                return Err(Status::internal(format!(
                    "Failed to send transcoding task: {}",
                    e
                )));
            }
        }

        let response = TranscodeResponse {
            status_code: 200,
            message: "Transcoding task queued".to_string(),
            cid: source_cid,
        };

        Ok(Response::new(response))
    }

    async fn get_transcoded(
        &self,
        request: Request<GetTranscodedRequest>,
    ) -> Result<Response<GetTranscodedResponse>, Status> {
        let source_cid = request.get_ref().source_cid.clone();

        let transcoded = TRANSCODED.lock().await;
        let metadata = transcoded.get(&source_cid).cloned().ok_or_else(|| {
            Status::not_found(format!("CID not found for source_cid: {}", source_cid))
        })?;

        let response = GetTranscodedResponse {
            status_code: 200,
            metadata,
        };
        println!(
            "get_transcoded Response: {}, {}",
            response.status_code, response.metadata
        );

        Ok(Response::new(response))
    }
}

impl Drop for TranscodeServiceHandler {
    fn drop(&mut self) {
        self.transcode_task_sender = None;
    }
}

#[derive(Debug)]
struct TranscodeError(String);

impl warp::reject::Reject for TranscodeError {}

#[derive(Debug, Serialize)]
struct TranscodeResponseWrapper {
    status_code: i32,
    message: String,
}

impl From<transcode::TranscodeResponse> for TranscodeResponseWrapper {
    fn from(response: transcode::TranscodeResponse) -> Self {
        TranscodeResponseWrapper {
            status_code: response.status_code,
            message: response.message,
        }
    }
}

impl From<tokio::sync::mpsc::error::SendError<(String, bool, bool)>> for TranscodeError {
    fn from(e: tokio::sync::mpsc::error::SendError<(String, bool, bool)>) -> Self {
        TranscodeError(format!("Failed to send transcoding task: {}", e))
    }
}

#[derive(Debug, Clone)]
struct RestHandler {
    transcode_task_sender: Option<Arc<Mutex<mpsc::Sender<(String, bool, bool)>>>>,
}

impl RestHandler {
    async fn transcode(
        &self,
        source_cid: String,
        is_gpu: bool,
        is_encrypt: bool,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if let Some(ref sender) = self.transcode_task_sender {
            let sender = sender.lock().await.clone();

            if let Err(e) = sender.send((source_cid.clone(), is_gpu, is_encrypt)).await {
                return Err(warp::reject::custom(TranscodeError::from(e)));
            }
        }

        let response = transcode::TranscodeResponse {
            status_code: 200,
            message: "Transcoding task queued".to_string(),
            cid: source_cid,
        };

        Ok(warp::reply::json(&TranscodeResponseWrapper::from(response)))
    }
}

#[derive(Debug, Serialize)]
struct GetTranscodedResponseWrapper {
    status_code: i32,
    metadata: String,
}

impl From<transcode::GetTranscodedResponse> for GetTranscodedResponseWrapper {
    fn from(response: transcode::GetTranscodedResponse) -> Self {
        GetTranscodedResponseWrapper {
            status_code: response.status_code,
            metadata: response.metadata,
        }
    }
}

impl RestHandler {
    async fn get_transcoded(
        &self,
        source_cid: String,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let transcoded = TRANSCODED.lock().await;
        let metadata = transcoded
            .get(&source_cid)
            .cloned()
            .ok_or_else(|| warp::reject::not_found())?;

        let response = GetTranscodedResponse {
            status_code: 200,
            metadata,
        };

        Ok(warp::reply::json(&GetTranscodedResponseWrapper::from(
            response,
        )))
    }
}

pub mod transcode {
    tonic::include_proto!("transcode");
}

// Define a struct to receive the query parameters.
#[derive(Deserialize)]
struct QueryParams {
    source_cid: String,
    is_gpu: bool,
    is_encrypt: bool,
}

/// The main entry point for the transcode server. Initializes the server
/// with the specified configuration, starts the gRPC server, and listens
/// for incoming requests. Once a request is received, it spawns a new thread
/// to handle the request and continues listening for more requests.
///
#[tokio::main]
async fn main() {
    dotenv().ok();

    // Create a channel for transcoding tasks
    let (task_sender, task_receiver) = mpsc::channel::<(String, bool, bool)>(100);
    let task_receiver = Arc::new(Mutex::new(task_receiver));

    // Start the transcoding task receiver
    let receiver_clone = Arc::clone(&task_receiver);
    tokio::spawn(transcode_task_receiver(receiver_clone));

    // Wrap task_sender in an Arc<Mutex<>> before passing it to handlers
    let task_sender = Arc::new(Mutex::new(task_sender));

    // Create a gRPC server
    let grpc_addr = "0.0.0.0:50051"
        .parse()
        .expect("Invalid gRPC server address");

    let transcode_service_handler = TranscodeServiceHandler {
        transcode_task_sender: Some(task_sender.clone()),
    };
    let transcode_service_server = TranscodeServiceServer::new(transcode_service_handler);
    let grpc_server = Server::builder()
        .add_service(transcode_service_server)
        .serve(grpc_addr);

    // Create a REST server
    let rest_handler = RestHandler {
        transcode_task_sender: Some(task_sender.clone()),
    };

    let rest_handler_transcode = RestHandler {
        transcode_task_sender: Some(task_sender.clone()),
    };

    let rest_handler_get_transcoded = RestHandler {
        transcode_task_sender: Some(task_sender.clone()),
    };

    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["POST", "GET"])
        .allow_headers(vec!["Content-Type"]);

    // Modify the transcode endpoint to use warp::query().
    let transcode = warp::path!("transcode")
        .and(warp::query::<QueryParams>())
        .and_then(move |params: QueryParams| {
            let rest_handler = rest_handler_transcode.clone();
            async move {
                rest_handler
                    .transcode(params.source_cid, params.is_gpu, params.is_encrypt)
                    .await
            }
        })
        .with(cors.clone())
        .boxed();

    let get_transcoded = warp::path!("get_transcoded" / String)
        .and_then(move |source_cid| {
            let rest_handler = rest_handler_get_transcoded.clone();
            async move { rest_handler.get_transcoded(source_cid).await }
        })
        .with(cors.clone())
        .boxed();

    let routes = transcode.or(get_transcoded);
    let rest_server = warp::serve(routes).run(([0, 0, 0, 0], 8000));

    // Run both servers concurrently, and print a message when each finishes.
    let grpc_server = tokio::spawn(grpc_server);
    let rest_server = tokio::spawn(rest_server);

    match grpc_server.await {
        Ok(_) => println!("gRPC server shut down gracefully."),
        Err(e) => eprintln!("gRPC server error: {}", e),
    }
    match rest_server.await {
        Ok(_) => println!("REST server shut down gracefully."),
        Err(e) => eprintln!("REST server error: {}", e),
    }
}
