/*
 * server.rs
 *
 * This file contains code for transcoding a video using ffmpeg.
 * Upload a video in h264 format and it will be transcoded to 2 h264 mp4 files;
 * one in 1080p format and another in 720p.
 * This is then uploaded to decentralised SIA Storage via S5.
 *
 * Author: Jules Lai
 * Date: 1 March 2023
 */

mod s5;
use s5::{download_file, upload_video};

use tonic::{transport::Server, Request, Response, Status};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use sanitize_filename::sanitize;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use transcode::{
    transcode_service_server::{TranscodeService, TranscodeServiceServer},
    GetCidRequest, GetCidResponse, TranscodeRequest, TranscodeResponse,
};

use dotenv::dotenv;

static VIDEO_CID: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::from("")));
static VIDEO_CID1: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::from("")));
static VIDEO_CID2: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::from("")));
static PATH_TO_FILE: &str = "path/to/file/";

// The transcoding task receiver, which receives transcoding tasks from the gRPC server
async fn transcode_task_receiver(receiver: Arc<Mutex<mpsc::Receiver<String>>>) {
    while let Some(file_path) = receiver.lock().await.recv().await {
        println!("Transcoding video: {}", &file_path);
        if let Err(e) = transcode_video(&file_path).await {
            eprintln!("Failed to transcode {}: {}", &file_path, e);
        }
    }
}

// Transcodes a video file to 1080p and 720p h264 mp4 formats using ffmpeg
async fn transcode_video(url: &str) -> Result<Response<TranscodeResponse>, Status> {
    println!("Downloading video from: {}", url);

    let mut video_cid = VIDEO_CID.lock().await;
    *video_cid = url.to_string();

    let file_name = sanitize(url);
    let file_path = String::from(PATH_TO_FILE.to_owned() + &file_name);

    match download_file(url, file_path.as_str()) {
        Ok(()) => println!("File downloaded successfully"),
        Err(e) => eprintln!("Error downloading file: {}", e),
    }

    println!("Transcoding video: {}", &file_path);

    let mut cmd = Command::new("ffmpeg");
    cmd.args([
        "-i",
        file_path.as_str(),
        "-c:v",
        "libx264",
        "-preset",
        "medium",
        "-crf",
        "23",
        "-c:a",
        "aac",
        "-b:a",
        "128k",
        "-ac",
        "2",
        "-s",
        "hd1080",
        "-y",
        format!("./temp/to/transcode/{}_1080p.mp4", &file_name).as_str(),
    ]);
    let output = cmd.output().expect("Failed to execute command");
    println!("{:?}", output);

    println!("Before2: let cmd = format!(");

    let mut cmd2 = Command::new("ffmpeg");
    cmd2.args([
        "-i",
        file_path.as_str(),
        "-c:v",
        "libx264",
        "-preset",
        "medium",
        "-crf",
        "23",
        "-c:a",
        "aac",
        "-b:a",
        "128k",
        "-ac",
        "2",
        "-s",
        "hd720",
        "-y",
        format!("./temp/to/transcode/{}_720p.mp4", &file_name).as_str(),
    ]);

    let output2 = cmd2.output().expect("Failed to execute command");
    println!("{:?}", output2);

    // Upload the transcoded videos to storage
    let mut response: TranscodeResponse;
    match upload_video(format!("./temp/to/transcode/{}_1080p.mp4", file_name).as_str()) {
        Ok(cid) => {
            println!(
                "******************************************1080p cid: {}",
                &cid
            );

            let mut video_cid1 = VIDEO_CID1.lock().await;
            *video_cid1 = cid;

            response = TranscodeResponse {
                status_code: 200,
                message: "Transcoding task finished".to_string(),
            };
        }
        Err(e) => {
            println!("!!!!!!!!!!!!!!!!!!!!!1080p no cid");

            response = TranscodeResponse {
                status_code: 500,
                message: format!("Transcoding task failed with error {}", e),
            };
        }
    };

    match upload_video(format!("./temp/to/transcode/{}_720p.mp4", file_name).as_str()) {
        Ok(cid) => {
            response = TranscodeResponse {
                status_code: 200,
                message: "Transcoding task finished".to_string(),
            };

            println!(
                "******************************************720p cid: {}",
                &cid
            );

            let mut video_cid2 = VIDEO_CID2.lock().await;
            *video_cid2 = cid;
        }
        Err(e) => {
            response = TranscodeResponse {
                status_code: 500,
                message: format!("Transcoding task failed with error {}", e),
            };
        }
    };

    //    Ok(())

    Ok(Response::new(response))
}

// The gRPC service implementation
#[derive(Debug, Clone)]
struct TranscodeServiceHandler {
    transcode_task_sender: Option<Arc<Mutex<mpsc::Sender<String>>>>,
}

#[async_trait]
impl TranscodeService for TranscodeServiceHandler {
    async fn transcode(
        &self,
        request: Request<TranscodeRequest>,
    ) -> Result<Response<TranscodeResponse>, Status> {
        let url = request.get_ref().url.to_string();
        println!("Received URL: {}", url);

        println!(
            "transcode_task_sender is None: {}",
            self.transcode_task_sender.is_none()
        );
        // Send the transcoding task to the transcoding task receiver
        if let Some(ref sender) = self.transcode_task_sender {
            println!("Before: if let Err(e) = sender.send(file_path).await");

            let mut sender = sender.lock().await.clone();
            if let Err(e) = sender.send(url).await {
                return Err(Status::internal(format!(
                    "Failed to send transcoding task: {}",
                    e
                )));
            }
        }

        let response = TranscodeResponse {
            status_code: 200,
            message: "Transcoding task queued".to_string(),
        };

        Ok(Response::new(response))
    }

    async fn get_cid(
        &self,
        request: Request<GetCidRequest>,
    ) -> Result<Response<GetCidResponse>, Status> {
        let resolution = request.get_ref().resolution.as_str();

        // Assuming `resolution` is already defined and contains the resolution value
        let cidOption = match resolution {
            "1080p" => Some(VIDEO_CID1.lock().await.to_string()),
            "720p" => Some(VIDEO_CID2.lock().await.to_string()),
            _ => None,
        };

        let cid = cidOption
            .as_ref()
            .map_or_else(|| String::new(), |s| s.to_string());

        let response = GetCidResponse {
            status_code: if cidOption.is_some() { 200 } else { 404 },
            cid: cid.clone(),
        };
        println!(
            "get_cid Response: {}, {}",
            response.status_code, response.cid
        );

        Ok(Response::new(response))
    }
}

impl Drop for TranscodeServiceHandler {
    fn drop(&mut self) {
        self.transcode_task_sender = None;
    }
}

pub mod transcode {
    tonic::include_proto!("transcode");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    // Create a channel for transcoding tasks
    let (task_sender, task_receiver) = mpsc::channel(100);
    let task_receiver = Arc::new(Mutex::new(task_receiver));

    // Start the transcoding task receiver
    let receiver_clone = Arc::clone(&task_receiver);
    tokio::spawn(transcode_task_receiver(receiver_clone));

    // Create a gRPC server
    let addr = "0.0.0.0:50051".parse()?;

    // Wrap task_sender in an Arc<Mutex<>> before passing it to TranscodeServiceHandler
    let task_sender = Arc::new(Mutex::new(task_sender));

    let transcode_service_handler = TranscodeServiceHandler {
        transcode_task_sender: Some(task_sender),
    };
    let transcode_service_server = TranscodeServiceServer::new(transcode_service_handler);
    Server::builder()
        .add_service(transcode_service_server)
        .serve(addr)
        .await?;

    Ok(())
}
