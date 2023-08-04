use async_trait::async_trait;
use base64::{engine::general_purpose, DecodeError, Engine as _};

use sanitize_filename::sanitize;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;

use dotenv::{dotenv, var};

use crate::encrypt_file::encrypt_file_xchacha20;
use crate::s5::hash_blake3_file;
use crate::s5::{download_file, upload_video};

use std::path::Path;

use crate::encrypted_cid::create_encrypted_cid;

use tonic::{transport::Server, Code, Request, Response, Status};

use serde::{Deserialize, Serialize};
use serde_json;

use std::error::Error;
use std::fs::metadata;
use std::fs::{File, OpenOptions};
use std::io::Write;

use tokio::fs;
use tokio::io::AsyncReadExt;

use transcode::{
    transcode_service_server::{TranscodeService, TranscodeServiceServer},
    GetTranscodedRequest, GetTranscodedResponse, TranscodeRequest, TranscodeResponse,
};

static PATH_TO_FILE: &str = "path/to/file/";

pub mod transcode {
    tonic::include_proto!("transcode");
}

/// Downloads a video from the specified `url` from S5 and saves it to disk. The
/// downloaded file is saved to the directory specified by the `PATH_TO_FILE`
/// environment variable, with a filename based on the URL. Returns the path
/// to the downloaded file as a `String`.
///
/// # Arguments
///
/// * `url` - The URL of the video to download.
///
pub async fn download_video(url: &str) -> Result<String, Status> {
    println!("Downloading video from: {}", url);

    let file_name = sanitize(url);

    let path_to_file = var("PATH_TO_FILE").unwrap();
    let file_path = String::from(path_to_file.to_owned() + &file_name);

    match download_file(url, file_path.as_str()) {
        Ok(()) => println!("File downloaded successfully"),
        Err(e) => {
            eprintln!("Error downloading file: {}", e);
            return Err(Status::new(
                Code::Internal,
                format!("Error downloading file: {}", e),
            ));
        }
    }

    Ok(file_path)
}

#[derive(Debug, Deserialize)]
struct VideoFormat {
    id: u32,
    ext: String,
    vcodec: String,
    preset: String,
    profile: String,
    ch: u8,
    vf: String,
    b_v: String,
    ar: String,
    gpu: bool,
}

/// Transcodes the video at the specified `input_path` using ffmpeg
/// and saves the resulting output to the specified `output_path`.
/// Returns the path to the transcoded video as a `String`.
///
/// # Arguments
///
/// * `input_path` - The path to the input video file.
/// * `output_path` - The path to save the transcoded video file.
/// * `transcoder` - The transcoder to use for transcoding the video.
///
pub async fn transcode_video(
    file_path: &str,
    video_format: &str,
    is_gpu: bool,
    is_encrypt: bool,
) -> Result<Response<TranscodeResponse>, Status> {
    println!("Processing video at: {}", file_path);

    let unsanitized_file_name = Path::new(file_path)
        .file_name()
        .ok_or_else(|| Status::new(Code::InvalidArgument, "Invalid file path"))?
        .to_string_lossy()
        .to_string();

    let file_name = sanitize(&unsanitized_file_name);

    println!("Transcoding video: {}", &file_path);
    println!("is_gpu = {}", &is_gpu);

    let mut encryption_key1: Vec<u8> = Vec::new();
    let mut encryption_key2: Vec<u8> = Vec::new();

    let mut response: TranscodeResponse;

    let format: VideoFormat = serde_json::from_str::<VideoFormat>(video_format).map_err(|err| {
        Status::new(
            Code::InvalidArgument,
            format!("Invalid video format: {}", err),
        )
    })?;

    if is_gpu {
        println!("GPU transcoding");

        let mut cmd = Command::new("ffmpeg");
        cmd.args([
            "-i",
            file_path,
            "-c:v",
            &format.vcodec,
            "-b:v",
            &format.b_v,
            "-c:a",
            "libopus", // Keep this as-is, if not present in VideoFormat
            "-b:a",
            "192k", // Keep this as-is, if not present in VideoFormat
            "-ac",
            &format.ch.to_string(),
            "-vf",
            &format.vf,
            "-y",
            format!("./temp/to/transcode/{}_ue.mp4", &file_name).as_str(),
        ]);

        let output = cmd.output().expect("Failed to execute command");
        println!("{:?}", output);

        match encrypt_file_xchacha20(
            format!("./temp/to/transcode/{}_ue.mp4", file_name),
            format!("./temp/to/transcode/{}.mp4", file_name),
            0,
        ) {
            Ok(bytes) => {
                // Encryption succeeded, and `bytes` contains the encrypted data
                // Add your success handling code here
                encryption_key1 = bytes;
                println!("Encryption succeeded");
            }
            Err(error) => {
                // Encryption failed
                // Handle the error here
                eprintln!("Encryption error: {:?}", error);
                // Optionally, you can return an error or perform error-specific handling
            }
        }
    } else {
        println!("CPU transcoding");

        let mut cmd = Command::new("ffmpeg");
        cmd.args([
            "-i",
            file_path,
            "-c:v",
            "libaom-av1", // use libaom-av1 encoder for AV1
            "-cpu-used",
            "4", // set encoding speed to 4 (range 0-8, lower is slower)
            "-b:v",
            "0", // use constant quality mode
            "-crf",
            "30", // set quality level to 30 (range 0-63, lower is better)
            "-c:a",
            "libopus", // use libopus encoder for audio
            "-b:a",
            "128k",
            "-ac",
            "2",
            "-s",
            "hd1080",
            "-y",
            format!("./temp/to/transcode/{}.mp4", &file_name).as_str(), // change output extension to .av1
        ]);
        let output = cmd.output().expect("Failed to execute command");
        println!("{:?}", output);
    }

    if (is_encrypt) {
        let file_path = format!("./temp/to/transcode/{}_ue.mp4", file_name);
        let file_path_encrypted = format!("./temp/to/transcode/{}.mp4", file_name);

        let hash_result = hash_blake3_file(file_path.clone());
        let hash_result_encrypted = hash_blake3_file(file_path_encrypted.to_owned());

        let cid_type_encrypted: u8 = 0xae; // replace with your actual cid type encrypted
        let encryption_algorithm: u8 = 0xa6; // replace with your actual encryption algorithm
        let chunk_size_as_power_of_2: u8 = 18; // replace with your actual chunk size as power of 2
        let padding: u32 = 0; // replace with your actual padding

        // Upload the transcoded videos to storage
        match upload_video(file_path_encrypted.as_str()) {
            Ok(cid_encrypted) => {
                println!(
                    "******************************************2160p cid: {:?}",
                    &cid_encrypted
                );

                let mut hash = Vec::new();
                match hash_result {
                    Ok(hash1) => {
                        hash = hash1.as_bytes().to_vec();
                        // Now you can use bytes as needed.
                    }
                    Err(err) => {
                        eprintln!("Error computing blake3 hash: {}", err);

                        return Err(Status::new(
                            Code::Internal,
                            format!("Error computing blake3 hash: {}", err),
                        ));
                    }
                }

                let mut hash_encrypted = Vec::new();
                match hash_result_encrypted {
                    Ok(hash1) => {
                        hash_encrypted = hash1.as_bytes().to_vec();
                        // Now you can use bytes as needed.
                    }
                    Err(err) => {
                        eprintln!("Error computing blake3 hash: {}", err);

                        return Err(Status::new(
                            Code::Internal,
                            format!("Error computing blake3 hash: {}", err),
                        ));
                    }
                }

                let mut encrypted_blob_hash = vec![0x1f];
                encrypted_blob_hash.extend(hash_encrypted);

                let cloned_hash = encrypted_blob_hash.clone();

                let file_path_path = Path::new(&file_path);
                let metadata = std::fs::metadata(file_path_path).expect("Failed to read metadata");
                let file_size = metadata.len();

                let cid = hash_bytes_to_cid(hash, file_size);

                println!("encryption_key1: {:?}", encryption_key1);
                println!("cid_encrypted: {:?}", cid_encrypted);
                println!("cid: {:?}", cid);

                println!(
                    "upload_video Ok: encrypted_blob_hash = {:?}",
                    hex::encode(&encrypted_blob_hash)
                );
                println!(
                    "upload_video Ok: encryption_key1 = {:?}",
                    hex::encode(&encryption_key1)
                );
                println!("upload_video Ok: cid = {:?}", hex::encode(&cid));

                let hash = hash_blake3_file(file_path_encrypted).unwrap();
                println!(
                    "`upload_video: encryptedBlobMHashBase64url` = {}",
                    general_purpose::URL_SAFE_NO_PAD
                        .encode([&[31u8] as &[_], hash.as_bytes()].concat())
                );

                let encrypted_cid_bytes = create_encrypted_cid(
                    cid_type_encrypted,
                    encryption_algorithm,
                    chunk_size_as_power_of_2,
                    encrypted_blob_hash,
                    encryption_key1,
                    padding,
                    cid,
                );

                println!(
                    "upload_video Ok: encrypted_cid_bytes = {:?}",
                    hex::encode(&encrypted_cid_bytes)
                );
                let encrypted_cid = format!("u{}", bytes_to_base64url(&encrypted_cid_bytes));
                println!("upload_video Ok: encrypted_cid = {}", encrypted_cid);

                // Now you have your encrypted_blob_hash and encrypted_cid
                println!("Encrypted Blob Hash: {:02x?}", cloned_hash);
                println!("Encrypted CID: {:?}", encrypted_cid);

                println!("Transcoding task finished");

                // Return the TranscodeResponse with the job ID
                response = TranscodeResponse {
                    status_code: 200,
                    message: String::from("Transcoding successful"),
                    cid: encrypted_cid,
                };
            }
            Err(e) => {
                println!("!!!!!!!!!!!!!!!!!!!!!2160p no cid");
                println!("Error: {}", e); // This line is added to print out the error message

                response = TranscodeResponse {
                    status_code: 500,
                    message: format!("Transcoding task failed with error {}", e),
                    cid: "".to_string(),
                };
            }
        };
    } else {
        let file_path = format!("./temp/to/transcode/{}.mp4", file_name);

        // Upload the transcoded videos to storage
        match upload_video(file_path.as_str()) {
            Ok(cid_bytes) => {
                let cid = format!("u{}", bytes_to_base64url(&cid_bytes));
                println!("cid: {:?}", cid);

                println!("Transcoding task finished");

                // Return the TranscodeResponse with the job ID
                response = TranscodeResponse {
                    status_code: 200,
                    message: String::from("Transcoding successful"),
                    cid,
                };
            }
            Err(e) => {
                println!("!!!!!!!!!!!!!!!!!!!!!2160p no cid");
                println!("Error: {}", e); // This line is added to print out the error message

                response = TranscodeResponse {
                    status_code: 500,
                    message: format!("Transcoding task failed with error {}", e),
                    cid: "".to_string(),
                };
            }
        };
    }

    Ok(Response::new(response))
}

pub fn bytes_to_base64url(bytes: &[u8]) -> String {
    let engine = general_purpose::STANDARD_NO_PAD;

    let mut base64_string = engine.encode(bytes);

    // Replace standard base64 characters with URL-safe ones
    base64_string = base64_string.replace("+", "-").replace("/", "_");

    base64_string
}

pub fn base64url_to_bytes(base64url: &str) -> Vec<u8> {
    let engine = general_purpose::STANDARD_NO_PAD;

    println!("base64url_to_bytes: base64url = {}", base64url);

    // Replace URL-safe characters with standard base64 ones
    let base64 = base64url
        .replace("-", "+")
        .replace("_", "/")
        .replace("=", "");

    engine.decode(&base64).unwrap()
}

pub fn hash_bytes_to_cid(hash: Vec<u8>, file_size: u64) -> Vec<u8> {
    // Decode the base64url hash back to bytes
    // Prepend the byte 0x26 before the full hash
    let mut bytes = hash.to_vec();
    bytes.insert(0, 0x1f);
    bytes.insert(0, 0x26);

    // Append the size of the file, little-endian encoded
    let le_file_size = &file_size.to_le_bytes();
    let mut trimmed = le_file_size.as_slice();

    // Remove the trailing zeros
    while let Some(0) = trimmed.last() {
        trimmed = &trimmed[..trimmed.len() - 1];
    }

    bytes.extend(trimmed);

    bytes
}

#[derive(Debug, Deserialize)]
struct Location {
    parts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JsonData {
    locations: Vec<Location>,
}

pub async fn download_and_concat_files(
    data: String,
    file_path: String,
) -> Result<(), Box<dyn Error>> {
    // Parse the JSON data
    let json_data: JsonData = serde_json::from_str(&data)?;

    // Open the final file
    let mut final_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)
        .expect("Failed to open final_file");

    for (location_index, location) in json_data.locations.iter().enumerate() {
        let last_part_index = location.parts.len() - 1;
        for (part_index, part) in location.parts.iter().enumerate() {
            if location_index == json_data.locations.len() - 1 && part_index == last_part_index {
                continue;
            }

            println!("download_and_concat_files part: {}", part);

            let tmp_file_path = download_video(&part).await?;

            let mut downloaded_file = match fs::File::open(&tmp_file_path).await {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open downloaded file {}: {}", &tmp_file_path, e);
                    continue;
                }
            };
            let mut buffer = Vec::new();
            downloaded_file.read_to_end(&mut buffer).await?;

            println!("Size of buffer: {}", buffer.len());

            // Append the content to the final file
            final_file.write_all(&buffer)?;

            let file_size = metadata(&file_path)?.len();
            println!("Size of final file: {} bytes", file_size);

            // Delete the downloaded file
            fs::remove_file(tmp_file_path).await?;
        }
    }

    Ok(())
}
