# Fabstir transcoder

## Summary

This transcoder server can convert from any video format ffmpeg supports to AV1 codec. AV1 is an open-source, royalty-free video codec that has better compression than h264 with smaller file sizes and hence less bandwidth. There is also support to transcode to h264, higher resolutions and frame rates.
AV1 is already supported by a number of popular browsers, including Google Chrome, Mozilla Firefox, and Microsoft Edge. It is also supported by a growing number of video players and streaming services.

## Encoding

AV1 compression requires much more complexity than h264. Even with top of the line CPU, encoding rates are much less than real-time. Hardware encoding is realistically required and this is available on GPUs such as NVIDIA RTX 4000 series, NVIDIA A6000 or Intel Arc GPUs.

## Encryption

The transcoder offers two forms of operation; either the source video is encrypted and the transcoder will also encrypt the transcoded videos, or the source video is not encrypted thus the transcoded videos will not be encrypted.

## Technology used

The transcoder network integrates to S5 for its content delivery network (CDN) and its ability to store content to Sia cloud storage.

S5 is a content-addressed storage network similar to IPFS, but with some new concepts and ideas to make it more efficient and powerful.
https://github.com/s5-dev

Sia is a decentralized cloud storage platform that uses blockchain technology to store data https://sia.tech/. It is designed to be more secure, reliable, and affordable than traditional cloud storage providers. Sia encrypts and distributes your files across a decentralized network of hosts. This means that your data is not stored in a single location, and it is not accessible to anyone who does not have the encryption key.

# To get started
```
cd transcode_server
cargo build
cargo run transcode-server
```

# To use

Either use http/2:
The `.proto` file
```
message TranscodeRequest {
    string source_cid = 1;
    string video_formats = 2;
    bool is_encrypted = 3;
    bool is_gpu = 4;
}

message TranscodeResponse {
    int32 status_code = 1;
    string message = 2;
    string cid = 3;
}

service TranscodeService {
    rpc Transcode(TranscodeRequest) returns (TranscodeResponse);

    rpc GetTranscoded(GetTranscodedRequest) returns (GetTranscodedResponse);
}

message GetTranscodedRequest {
    string source_cid = 1;
}

message GetTranscodedResponse {
    int32 status_code = 1;
    string metadata = 2;
}
```

Or http/1:
use port: 50051

```
      const isEncrypted = false;
      const isGPU = true;
      const cid = `${PORTAL_URL}/s5/blob/${uploadedFileCID}`;

      const videoFormats = [
        {
          id: 32,
          label: "1080p",
          type: "video/mp4",
          ext: "mp4",
          vcodec: "av1_nvenc",
          preset: "medium",
          profile: "main",
          ch: 2,
          vf: "scale=1920x1080",
          b_v: "4.5M",
          ar: "44k",
          gpu: true,
        },
        {
          id: 34,
          label: '2160p',
          type: 'video/mp4',
          ext: 'mp4',
          vcodec: 'av1_nvenc',
          preset: 'slower',
          profile: 'high',
          ch: 2,
          vf: 'scale=3840x2160',
          b_v: '18M',
          ar: '48k',
          gpu: true,
        },
      ];

const url = `${TRANSCODER_CLIENT_URL}/transcode?source_cid=${cid}&video_formats=${videoFormatsJSON}&is_encrypted=${isEncrypted}&is_gpu=${isGPU}`;
try {
        const response = await fetch(url, { method: "POST" });
        const data = await response.json();
      } catch (error) {
        console.error(error);
      }
}
```
