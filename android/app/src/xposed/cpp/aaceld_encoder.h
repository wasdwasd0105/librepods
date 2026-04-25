/*
    LibrePods - AirPods liberated from Apple's ecosystem
    Copyright (C) 2025 LibrePods contributors

    AAC-ELD encoder wrapper for Apple's vendor A2DP codec (0x004C / 0x8001).

    No third-party dependency: Android's libbluetooth_jni.so already ships a
    statically linked libfdk-aac (it drives the standard A2DP AAC codec
    path), so we resolve aacEnc{Open,Close,Encode,oder_SetParam,Info} from
    that library at hook-install time and call them directly. See
    aaceld_fdk_bind.* for the offset-driven resolution.

    Pipeline per RTP packet (30 ms, 3 AUs of 480 samples @ 48 kHz stereo):
        PCM(480 * 2ch * s16le) --FDK-AAC-> raw AU bytes --prefix 4B Apple header
    3 framed AUs are concatenated into the RTP payload; rtp_ts += 1440.
*/

#pragma once

#include <cstddef>
#include <cstdint>

namespace librepods::aaceld {

struct EncoderConfig {
    uint32_t sample_rate = 48000;   // fixed for Apple mode 130
    uint32_t bitrate = 265000;      // CBR; aac-eld-apple.md "working" value
    uint32_t granule_length = 480;  // 10 ms @ 48 kHz
    uint8_t channels = 2;
    bool sbr_enabled = false;       // AirPods sink is unstable with SBR
};

// Apple per-frame header (see aac-eld-apple.md §"RTP Payload Structure")
struct __attribute__((packed)) AppleFrameHeader {
    uint8_t b0;
    uint8_t b1;
    uint8_t b2;
    uint8_t b3;
};

constexpr size_t kAppleHeaderBytes = 4;
constexpr uint32_t kMaxAuSize = 0x7FF;
constexpr uint32_t kSequenceMask = 0x0FFF;
constexpr uint32_t kFramesPerRtpPacket = 3;
constexpr uint32_t kSamplesPerFrame = 480;
constexpr uint32_t kRtpTimestampStep = kFramesPerRtpPacket * kSamplesPerFrame; // 1440

class Encoder {
public:
    Encoder();
    ~Encoder();

    Encoder(const Encoder&) = delete;
    Encoder& operator=(const Encoder&) = delete;

    bool init(const EncoderConfig& cfg);
    void close();
    bool reset();

    // Encode one 10 ms PCM frame (480 samples * channels, s16le interleaved).
    // Writes raw AU bytes to au_out, returns bytes written (0 on failure).
    size_t encodeFrame(const int16_t* pcm_in, size_t pcm_samples,
                       uint8_t* au_out, size_t au_cap);

    // Build the 4-byte Apple header for one encoded AU. Increments the
    // 12-bit internal frame sequence. Returns false if au_size > 2047.
    bool buildFrameHeader(uint32_t au_size, AppleFrameHeader* out);

    // Pack `frame_count` (usually 3) contiguous AUs (concatenated in `aus`)
    // with per-frame Apple headers into the RTP payload buffer.
    size_t packRtpPayload(const uint8_t* aus, const uint16_t* au_sizes,
                          size_t frame_count,
                          uint8_t* rtp_payload_out, size_t rtp_payload_cap);

    void resetSequence();
    uint32_t sequence() const { return frame_sequence_; }

    // Actual values reported by aacEncInfo after init (may differ from config).
    uint32_t actualFrameLength() const { return actual_frame_length_; }
    uint32_t actualInputChannels() const { return actual_input_channels_; }
    uint32_t maxOutBufBytes() const { return max_out_buf_bytes_; }

private:
    EncoderConfig cfg_{};
    void* aac_handle_ = nullptr;        // AACENCODER*
    uint32_t frame_sequence_ = 1;
    bool initialized_ = false;
    uint32_t actual_frame_length_ = 0;
    uint32_t actual_input_channels_ = 0;
    uint32_t max_out_buf_bytes_ = 0;
};

// --- FDK-AAC binding ----------------------------------------------------
// Resolves aacEnc{Open,Close,Encode,oder_SetParam,Info} from the loaded
// libbluetooth_jni.so by reading persist.librepods.fdk_*_offset. Returns
// true iff every function could be resolved (all five are required). Call
// once per process after the Bluetooth library has been mapped.
bool resolveFdkSymbols(uintptr_t libbluetooth_jni_base);
bool fdkResolved();

}  // namespace librepods::aaceld
