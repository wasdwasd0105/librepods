/*
    LibrePods - AirPods liberated from Apple's ecosystem
    Copyright (C) 2025 LibrePods contributors

    Opus-slot hijack: when the Android A2DP stack walks through its codec
    table it asks the Opus-family helpers for capability bytes, rate /
    channel / bitrate info, the equality predicate, and the encoder
    interface. We override every one of those to describe Apple's AAC-ELD
    vendor codec (0x004C / 0x8001) and to return our own FDK-AAC-backed
    encoder. The stack never knows the codec it was "Opus" — it sees a
    normal vendor codec and negotiates, encodes, and streams with it.

    A2DP source media codec info on the wire, per AVDTP §8.19.5 / A2DP
    spec v1.3 §4.3.2 (A2DP_MEDIA_CT_NON_A2DP = 0xFF):
        byte0 : LOSC (length-of-service-capability) = 13 (0x0D)
        byte1 : MediaType (audio = 0x00)
        byte2 : MediaCodecType = 0xFF (non-A2DP / vendor)
        3..6  : VendorId  (4 bytes little-endian)
        7..8  : VendorCodecId (2 bytes little-endian)
        9..13 : Vendor-specific (5 bytes, from aac-eld-apple.md)
    Total 14 bytes on the wire (LOSC byte included).
*/

#include "a2dp_aaceld_hook.h"

#include <android/log.h>
#include <sys/system_properties.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "aaceld_encoder.h"

#define LOG_TAG "AirPodsHook.A2DP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace librepods::aaceld {

namespace {
// Local copy of /proc/self/maps walker — upstream's l2c_fcr_hook.cpp
// keeps its own getModuleBase as a static (file-local) symbol, so we
// can't reach it from this translation unit. Duplicating it here is
// cheap and avoids leaking a non-static helper into the rest of the
// xposed library.
uintptr_t getModuleBase(const char* module_name) {
    FILE* fp = std::fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[1024];
    uintptr_t base = 0;
    while (std::fgets(line, sizeof(line), fp)) {
        if (!std::strstr(line, module_name)) continue;
        char* dash = std::strchr(line, '-');
        if (!dash) continue;
        *dash = '\0';
        base = std::strtoull(line, nullptr, 16);
        break;
    }
    std::fclose(fp);
    return base;
}
}  // namespace

namespace {

// ------------------------ constants ------------------------------------

constexpr uint32_t kAppleVendorId = 0x0000004Cu;
constexpr uint16_t kAppleAacEldCodecId = 0x8001u;

// AVDTP media codec info for Apple AAC-ELD. The 14-byte on-wire sequence
// consists of a 1-byte LOSC (13) prepended to the 13 capability bytes
// (vendor 4B + codec 2B + specific 5B + 2B padding used elsewhere).
// See aac-eld-apple.md §"AVDTP Codec Discovery / SEP Capability".
constexpr size_t kAppleCodecInfoBytes = 14;
constexpr uint8_t kAppleCodecInfo[kAppleCodecInfoBytes] = {
    0x0D,                        // LOSC: 13 bytes follow
    0x00,                        // media_type = audio
    0xFF,                        // media_codec_type = non-A2DP (vendor)
    0x4C, 0x00, 0x00, 0x00,      // vendor_id = 0x0000004C
    0x01, 0x80,                  // codec_id  = 0x8001
    0x00, 0x80,                  // object_type bitmap = AAC-ELD (0x0080)
    0x00, 0x8C,                  // freq=48kHz (0x008) | ch=mono|stereo (0xC)
    0x00,                        // reserved
    // VBR/bitrate bytes (3) would extend this blob to 17 bytes for the
    // full capability; stack-side SEP entries are typically truncated at
    // 14 bytes so we follow that convention. The full 17-byte form is
    // written directly into the advertised capability in the SEP hook.
};

// Full 17-byte SEP capability (Apple form from aac-eld-apple.md).
// NOTE: channel byte is 0x84 (stereo only), matching macOS's
// SET_CONFIGURATION bytes. The doc's §SEP Capability shows 0x8C
// (mono|stereo bitmap) for the caps-exchange phase, but on Android the
// same function A2DP_BuildInfoOpus is called for BOTH cap and set-config
// paths, and AirPods reject bitmaps in the SET_CONFIG frame (stream
// never reaches STATE_STARTED). Advertising stereo-only caps is still
// valid per AVDTP because AirPods sink only does stereo anyway.
constexpr size_t kAppleSepCapBytes = 17;
constexpr uint8_t kAppleSepCap[kAppleSepCapBytes] = {
    0x10,                        // LOSC: 16 bytes follow (tA2DP_OPUS_CIE
                                 //   builder emits 15..17 depending on
                                 //   codec; we use the longest form)
    0x00,                        // media_type = audio
    0xFF,                        // media_codec_type = non-A2DP (vendor)
    0x4C, 0x00, 0x00, 0x00,      // vendor_id little-endian
    0x01, 0x80,                  // codec_id  little-endian
    0x00, 0x80,                  // object_type = AAC-ELD
    0x00, 0x84,                  // freq=48k | ch=stereo ONLY (matches
                                 //   macOS SET_CONFIG; 0x8C breaks
                                 //   AirPods AVDTP_START on Pixel 10)
    0x00,                        // reserved
    0x83, 0xE8, 0x00,            // VBR=1, max bitrate = 256000
};

// Extract vendor+codec id from bytes 3..8 of an A2DP info blob.
static bool decodeVendorCodec(const uint8_t* p, uint32_t* vendor, uint16_t* codec) {
    if (!p || p[2] != 0xFF) return false;
    *vendor = (uint32_t)p[3] | ((uint32_t)p[4] << 8) |
              ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 24);
    *codec  = (uint16_t)p[7] | ((uint16_t)p[8] << 8);
    return true;
}

// Match Apple by vendor+codec id at bytes 3..8 of the A2DP info blob.
bool isAppleCodecInfo(const uint8_t* p_codec_info) {
    uint32_t vendor; uint16_t codec;
    if (!decodeVendorCodec(p_codec_info, &vendor, &codec)) return false;
    return vendor == kAppleVendorId && codec == kAppleAacEldCodecId;
}

// Match codec info that belongs to "our" stream — either Apple AAC-ELD
// (the real on-wire codec) OR the Opus IDs the stack stores internally
// after our blob substitution in the hijacked Opus slot.
constexpr uint32_t kOpusVendorId  = 0x000000E0u;
constexpr uint16_t kOpusCodecId   = 0x0001u;

bool isOurCodecInfo(const uint8_t* p_codec_info) {
    uint32_t vendor; uint16_t codec;
    if (!decodeVendorCodec(p_codec_info, &vendor, &codec)) return false;
    // Match Apple AAC-ELD (the real on-wire codec)
    if (vendor == kAppleVendorId && codec == kAppleAacEldCodecId) return true;
    // Match Opus (hijacked slot stores these after our blob substitution)
    if (vendor == kOpusVendorId && codec == kOpusCodecId) return true;
    return false;
}

// ------------------------ offset boilerplate ---------------------------

uintptr_t readOffsetProp(const char* property_name) {
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(property_name, value);
    if (len <= 0) return 0;

    const char* parse_start = value;
    if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) parse_start += 2;

    errno = 0;
    char* endptr = nullptr;
    uintptr_t offset = strtoul(parse_start, &endptr, 16);
    if (errno == 0 && endptr != parse_start && *endptr == '\0' && offset > 0) {
        LOGI("  %s = 0x%lx", property_name, (unsigned long)offset);
        return offset;
    }
    LOGW("Failed to parse %s value '%s'", property_name, value);
    return 0;
}

// ------------------------ encoder interface ----------------------------
// Mirrors AOSP's tA2DP_ENCODER_INTERFACE (system/include/stack/a2dp_codec_api.h)
// without pulling in the header. Offsets & sizes match AOSP trunk (Apr '26).

struct tA2DP_ENCODER_INIT_PEER_PARAMS {
    bool is_peer_edr;
    bool peer_supports_3mbps;
    uint16_t peer_mtu;
};

typedef uint32_t (*read_callback_t)(uint8_t* p_buf, uint32_t len);
typedef bool (*enqueue_callback_t)(void* /*BT_HDR*/ p_buf, size_t frames_n,
                                   uint32_t num_bytes);

struct tA2DP_ENCODER_INTERFACE {
    void (*encoder_init)(const tA2DP_ENCODER_INIT_PEER_PARAMS* peer_params,
                         void* a2dp_codec_config,
                         read_callback_t read_callback,
                         enqueue_callback_t enqueue_callback);
    void (*encoder_cleanup)();
    void (*feeding_reset)();
    void (*feeding_flush)();
    uint64_t (*get_encoder_interval_ms)();
    int (*get_effective_frame_size)();
    void (*send_frames)(uint64_t timestamp_us);
    void (*set_transmit_queue_length)(size_t queue_length);
};

// ------------------------ encoder state --------------------------------

// AVDT_MEDIA_OFFSET: AVDTP + RTP headers prepended by the stack before
// the payload hits L2CAP. 23 bytes on AOSP (4 AVDTP + 1 adapt + 12 RTP
// + padding/continuation). Our payload must fit within peer_mtu - this.
constexpr uint16_t kAvdtMediaOffset = 23;

struct EncoderState {
    std::mutex mu;
    Encoder encoder;
    read_callback_t read_cb = nullptr;
    enqueue_callback_t enqueue_cb = nullptr;
    uint32_t rtp_timestamp = 0;
    uint16_t max_payload = 0;   // peer_mtu − AVDT overhead; 0 = unlimited
    bool ready = false;
};
EncoderState g_enc;

// Forward BT_HDR layout used by the stack. We only write a header +
// payload via this struct. Field names match AOSP stack/include/bt_hdr.h.
struct BT_HDR {
    uint16_t event;
    uint16_t len;
    uint16_t offset;
    uint16_t layer_specific;
    uint8_t data[];
};

constexpr size_t kBtHdrPrefix = sizeof(BT_HDR);
constexpr size_t kRtpHeadroom = 64;  // BtaAvCo + AVDTP prepend up to 12B RTP
                                     //   + L2CAP + SNK headers in place

// ------------------------ encoder callbacks ----------------------------

void enc_init(const tA2DP_ENCODER_INIT_PEER_PARAMS* peer_params,
              void* /*a2dp_codec_config*/, read_callback_t read_callback,
              enqueue_callback_t enqueue_callback) {
    std::lock_guard<std::mutex> lk(g_enc.mu);
    g_enc.read_cb = read_callback;
    g_enc.enqueue_cb = enqueue_callback;
    g_enc.rtp_timestamp = 0;

    // Compute usable payload budget from the peer MTU.
    const uint16_t peer_mtu = peer_params ? peer_params->peer_mtu : 0;
    g_enc.max_payload = (peer_mtu > kAvdtMediaOffset)
                            ? (peer_mtu - kAvdtMediaOffset)
                            : 0;

    // Choose a bitrate that keeps 3 × (4-byte hdr + AU) within the MTU
    // *most* of the time. FDK-AAC CBR has significant bit-reservoir
    // variance (observed 1.56× peak/avg on Pixel), so we target 75% of
    // the theoretical ceiling to leave headroom. When a spike still
    // exceeds the MTU, enc_send_frames splits into multiple RTP packets
    // instead of discarding frames — so quality is preserved either way.
    //
    // For peer_mtu=1011: max_payload=988, max_au=325, ceiling=260 kbps,
    //   75% → 195 kbps. Floor is 196 kbps → target = 196 kbps.
    uint32_t target_bitrate = 196000;
    if (g_enc.max_payload > 0) {
        const uint32_t max_au_bytes =
            (g_enc.max_payload - kFramesPerRtpPacket * kAppleHeaderBytes)
            / kFramesPerRtpPacket;
        const uint32_t ceiling = max_au_bytes * 8 * 100;  // bits/sec
        // 75% of ceiling leaves room for CBR variance
        const uint32_t safe = ceiling * 3 / 4;
        if (safe > target_bitrate) target_bitrate = safe;
        if (target_bitrate > 265000) target_bitrate = 265000;
    }

    EncoderConfig cfg{};
    cfg.bitrate = target_bitrate;
    g_enc.ready = g_enc.encoder.init(cfg);
    LOGI("enc_init: peer_mtu=%u max_payload=%u bitrate=%u edr=%d 3mbps=%d ready=%d",
         peer_mtu, g_enc.max_payload, target_bitrate,
         peer_params ? (int)peer_params->is_peer_edr : -1,
         peer_params ? (int)peer_params->peer_supports_3mbps : -1,
         (int)g_enc.ready);
}

void enc_cleanup() {
    std::lock_guard<std::mutex> lk(g_enc.mu);
    g_enc.encoder.close();
    g_enc.ready = false;
    LOGI("enc_cleanup");
}

void enc_feeding_reset() {
    std::lock_guard<std::mutex> lk(g_enc.mu);
    g_enc.encoder.reset();
    g_enc.encoder.resetSequence();
    g_enc.rtp_timestamp = 0;
    LOGI("enc_feeding_reset");
}

void enc_feeding_flush() {
    enc_feeding_reset();
    LOGI("enc_feeding_flush");
}

uint64_t enc_get_encoder_interval_ms() {
    // 3 frames * 10 ms per packet (aac-eld-apple.md §Packet Timing).
    return 30;
}

int enc_get_effective_frame_size() {
    // One AAC-ELD AU plus the 4-byte Apple header. Average AU is ~303 B.
    return (int)(kAppleHeaderBytes + 320);
}

void enc_send_frames(uint64_t /*timestamp_us*/) {
    std::lock_guard<std::mutex> lk(g_enc.mu);
    static uint32_t s_invocations = 0;
    static uint32_t s_short_reads = 0;
    static uint32_t s_successful_sends = 0;
    ++s_invocations;
    if (!g_enc.ready || !g_enc.read_cb || !g_enc.enqueue_cb) {
        if (s_invocations <= 3)
            LOGW("enc_send_frames#%u: not ready (ready=%d read=%p enq=%p)",
                 s_invocations, (int)g_enc.ready, g_enc.read_cb, g_enc.enqueue_cb);
        return;
    }

    const uint32_t frame_length = g_enc.encoder.actualFrameLength();
    const uint32_t input_channels = g_enc.encoder.actualInputChannels();
    const size_t pcm_samples_per_frame = frame_length * input_channels;
    const size_t pcm_bytes_per_frame = pcm_samples_per_frame * sizeof(int16_t);
    constexpr size_t kAuCapPerFrame = 1024;
    const uint16_t max_payload = g_enc.max_payload;

    // ---- Phase 1: encode up to kFramesPerRtpPacket frames ---------------
    // Always consume a full 30 ms of PCM so the audio pipeline stays in
    // sync. Every encoded AU is kept — none are discarded.
    int16_t pcm[1024 * 2];
    uint8_t aus[kFramesPerRtpPacket * kAuCapPerFrame];
    uint16_t au_sizes[kFramesPerRtpPacket];
    size_t au_offsets[kFramesPerRtpPacket];
    size_t au_cursor = 0;
    uint32_t frames = 0;

    while (frames < kFramesPerRtpPacket) {
        uint32_t got = g_enc.read_cb(reinterpret_cast<uint8_t*>(pcm),
                                     (uint32_t)pcm_bytes_per_frame);
        if (got != pcm_bytes_per_frame) {
            if (frames == 0 && ++s_short_reads <= 5)
                LOGW("enc_send_frames#%u: short read %u/%zu",
                     s_invocations, (unsigned)got, pcm_bytes_per_frame);
            break;
        }
        size_t au_len = g_enc.encoder.encodeFrame(
            pcm, pcm_samples_per_frame, aus + au_cursor, kAuCapPerFrame);
        if (au_len == 0 || au_len > kAuCapPerFrame) {
            LOGE("encodeFrame returned %zu (frames=%u)", au_len, frames);
            break;
        }
        au_offsets[frames] = au_cursor;
        au_sizes[frames] = (uint16_t)au_len;
        au_cursor += au_len;
        ++frames;
    }
    if (frames == 0) return;

    // ---- Phase 2: pack into one or more MTU-safe RTP packets ------------
    // If all 3 AUs fit in one packet (typical), this sends exactly one.
    // When a CBR reservoir spike makes the payload too large, the excess
    // frames go into a second packet — no encoded data is ever dropped,
    // so the decoder's inter-frame prediction state stays in sync.
    uint32_t sent = 0;
    while (sent < frames) {
        // Determine how many of the remaining AUs fit in one packet.
        size_t pkt_payload = 0;
        uint32_t pkt_frames = 0;
        for (uint32_t i = sent; i < frames; ++i) {
            const size_t needed = kAppleHeaderBytes + au_sizes[i];
            if (max_payload > 0 && pkt_frames > 0 &&
                pkt_payload + needed > max_payload) {
                break;
            }
            pkt_payload += needed;
            ++pkt_frames;
        }
        if (pkt_frames == 0) {
            // Single AU exceeds MTU by itself — send it anyway (best
            // effort; L2CAP will fragment). Better than dropping it.
            pkt_frames = 1;
            pkt_payload = kAppleHeaderBytes + au_sizes[sent];
        }

        // Allocate BT_HDR with enough room for the payload + headroom.
        const size_t alloc = kBtHdrPrefix + kRtpHeadroom + pkt_payload;
        BT_HDR* p_buf = reinterpret_cast<BT_HDR*>(std::calloc(1, alloc));
        if (!p_buf) { LOGE("calloc BT_HDR failed"); return; }

        p_buf->offset = (uint16_t)kRtpHeadroom;
        uint8_t* payload = p_buf->data + p_buf->offset;

        // Pack the selected AUs (contiguous in `aus`) with Apple headers.
        size_t written = g_enc.encoder.packRtpPayload(
            aus + au_offsets[sent], au_sizes + sent,
            pkt_frames, payload, pkt_payload);
        if (written == 0) { std::free(p_buf); sent += pkt_frames; continue; }

        p_buf->len = (uint16_t)written;
        p_buf->layer_specific = pkt_frames;

        // Stash RTP timestamp in the 4 headroom bytes before payload.
        const uint32_t pkt_ts = g_enc.rtp_timestamp;
        payload[-4] = (uint8_t)(pkt_ts      );
        payload[-3] = (uint8_t)(pkt_ts >>  8);
        payload[-2] = (uint8_t)(pkt_ts >> 16);
        payload[-1] = (uint8_t)(pkt_ts >> 24);

        // AOSP's enqueue_callback takes ownership of p_buf unconditionally:
        // on success it enqueues; on failure (stream suspended / queue full)
        // it calls osi_free(p_buf) itself before returning false. We must
        // NOT free here — doing so would double-free and crash scudo.
        bool accepted = g_enc.enqueue_cb(p_buf, pkt_frames, (uint32_t)written);

        g_enc.rtp_timestamp += pkt_frames * frame_length;
        sent += pkt_frames;

        if (++s_successful_sends <= 10 || (s_successful_sends % 100) == 0) {
            LOGI("enc_send_frames#%u: pkt %u/%u frames, %zu bytes, "
                 "accepted=%d ts=%u au=[%u,%u,%u]",
                 s_invocations, pkt_frames, frames, written,
                 (int)accepted, g_enc.rtp_timestamp,
                 pkt_frames > 0 ? (unsigned)au_sizes[sent - pkt_frames] : 0,
                 pkt_frames > 1 ? (unsigned)au_sizes[sent - pkt_frames + 1] : 0,
                 pkt_frames > 2 ? (unsigned)au_sizes[sent - pkt_frames + 2] : 0);
        }
    }
}

void enc_set_transmit_queue_length(size_t queue_length) {
    LOGI("enc_set_transmit_queue_length: %zu", queue_length);
}

tA2DP_ENCODER_INTERFACE g_aaceld_interface = {
    .encoder_init = enc_init,
    .encoder_cleanup = enc_cleanup,
    .feeding_reset = enc_feeding_reset,
    .feeding_flush = enc_feeding_flush,
    .get_encoder_interval_ms = enc_get_encoder_interval_ms,
    .get_effective_frame_size = enc_get_effective_frame_size,
    .send_frames = enc_send_frames,
    .set_transmit_queue_length = enc_set_transmit_queue_length,
};

// ------------------------ hooks ----------------------------------------

// 1) A2DP_BuildInfoOpus(ie_ptr, out_buf) -> bool
//    AOSP source signature is (uint8_t, const tA2DP_OPUS_CIE*, uint8_t*),
//    but on Android 16 LTO specializes it to (const tA2DP_OPUS_CIE*,
//    uint8_t*) after const-folding media_type=AVDT_MEDIA_TYPE_AUDIO=0.
//    Verified via disassembly of libbluetooth_jni.so 0x856ee0 (Pixel 10
//    Pro, 2026-04-23): the compiled prologue reads only x0/x1 and stores
//    a fixed 0x0009 as the LOSC/media_type pair.
//    We ignore p_ie entirely and emit Apple's SEP capability into
//    p_result (17 bytes). Callers pass cfg->codec_info whose backing
//    buffer is AVDT_CODEC_SIZE = 20 bytes, so the 17-byte write fits.
using fn_build_info_opus_t = bool (*)(const void*, uint8_t*);
fn_build_info_opus_t original_build_info_opus = nullptr;
bool fake_build_info_opus(const void* /*p_ie*/, uint8_t* p_result) {
    if (!p_result) return false;
    std::memcpy(p_result, kAppleSepCap, kAppleSepCapBytes);
    LOGI("BuildInfoOpus -> emitted Apple AAC-ELD SEP (%zu bytes) @ %p",
         kAppleSepCapBytes, p_result);
    return true;
}

// 2) A2DP_VendorCodecTypeEqualsOpus(a, b) -> bool
//    Both args are A2DP codec-info blobs. The original compares the
//    vendor+codec-id 6 bytes; we just compare that both are Apple.
using fn_codec_type_equals_t = bool (*)(const uint8_t*, const uint8_t*);
fn_codec_type_equals_t original_codec_type_equals_opus = nullptr;
bool fake_codec_type_equals_opus(const uint8_t* a, const uint8_t* b) {
    const bool eq = isAppleCodecInfo(a) && isAppleCodecInfo(b);
    if (eq) LOGI("VendorCodecTypeEqualsOpus(Apple,Apple) -> true");
    return eq;
}

// 3) A2DP_VendorCodecEqualsOpus(a, b) -> bool
using fn_codec_equals_t = bool (*)(const uint8_t*, const uint8_t*);
fn_codec_equals_t original_codec_equals_opus = nullptr;
bool fake_codec_equals_opus(const uint8_t* a, const uint8_t* b) {
    if (!isAppleCodecInfo(a) || !isAppleCodecInfo(b)) return false;
    LOGI("VendorCodecEqualsOpus(Apple,Apple) -> true");
    return true;
}

// 4) A2DP_VendorGetEncoderInterfaceOpus(p_codec_info) ->
//        const tA2DP_ENCODER_INTERFACE*
using fn_get_encoder_iface_t =
    const tA2DP_ENCODER_INTERFACE* (*)(const uint8_t*);
fn_get_encoder_iface_t original_get_encoder_iface_opus = nullptr;
const tA2DP_ENCODER_INTERFACE* fake_get_encoder_iface_opus(
    const uint8_t* p_codec_info) {
    const bool ours = isOurCodecInfo(p_codec_info);
    if (ours) {
        LOGI("GetEncoderInterfaceOpus(ours=%d) -> AAC-ELD interface @ %p",
             (int)ours, &g_aaceld_interface);
        return &g_aaceld_interface;
    }
    return original_get_encoder_iface_opus
               ? original_get_encoder_iface_opus(p_codec_info)
               : nullptr;
}

// 5..10) integer-returning helpers hijacked to report AAC-ELD params.
using fn_int_from_info_t = int (*)(const uint8_t*);
fn_int_from_info_t original_get_sample_rate_opus = nullptr;
fn_int_from_info_t original_get_channel_count_opus = nullptr;
fn_int_from_info_t original_get_bits_per_sample_opus = nullptr;
fn_int_from_info_t original_get_bit_rate_opus = nullptr;
fn_int_from_info_t original_get_frame_size_opus = nullptr;
fn_int_from_info_t original_get_channel_mode_opus = nullptr;

int fake_get_sample_rate_opus(const uint8_t*)       { return 48000; }
int fake_get_channel_count_opus(const uint8_t*)     { return 2; }
int fake_get_bits_per_sample_opus(const uint8_t*)   { return 16; }
int fake_get_bit_rate_opus(const uint8_t*)          { return 265000; }
int fake_get_frame_size_opus(const uint8_t*)        { return kAppleHeaderBytes + 320; }
// AOSP "channel mode code" for stereo on A2DP AAC-family = 0x02.
int fake_get_channel_mode_opus(const uint8_t*)      { return 0x02; }

// 11) A2DP_IsVendorSourceCodecValid(info) -> bool
//     Catch-all so non-Opus callers (e.g. A2DP_VendorGetEncoderInterface
//     dispatcher) that check validity don't reject Apple info.
using fn_is_vendor_src_valid_t = bool (*)(const uint8_t*);
fn_is_vendor_src_valid_t original_is_vendor_src_valid = nullptr;
bool fake_is_vendor_src_valid(const uint8_t* p_codec_info) {
    if (isOurCodecInfo(p_codec_info)) return true;
    return original_is_vendor_src_valid
               ? original_is_vendor_src_valid(p_codec_info)
               : false;
}

// 12) A2DP_IsCodecValidOpus(info) -> bool
using fn_is_codec_valid_opus_t = bool (*)(const uint8_t*);
fn_is_codec_valid_opus_t original_is_codec_valid_opus = nullptr;
bool fake_is_codec_valid_opus(const uint8_t* p_codec_info) {
    const bool ok = isAppleCodecInfo(p_codec_info);
    if (ok) LOGI("IsCodecValidOpus(Apple) -> true");
    return ok;
}

// 13) A2DP_VendorSourceCodecIndex(info) -> btav_a2dp_codec_index_t
//     AOSP's table matches vendor_id+codec_id against known codecs
//     (CSR/Qualcomm/Sony/Google). Apple's IDs aren't in the table so an
//     Apple SEP received from AirPods gets dropped before reaching our
//     CodecTypeEqualsOpus / CodecEqualsOpus hooks. We claim Apple codec
//     for the Opus slot (= CODEC_INDEX_SOURCE_OPUS = 6) so the stack
//     routes the SEP through the Opus helpers, which we've already
//     replaced.
//     CODEC_INDEX_SOURCE_OPUS was verified by the boot-time log line
//     "initialized Source codec Opus, idx 6".
// Hijacked codec slot. CODEC_INDEX_SOURCE_OPUS = 6 on Android 16
// libbluetooth_jni.so. Constant rather than configurable — the hooks
// below all assume Opus-family symbols.
constexpr int g_codec_index_hijacked = 6;

using fn_vendor_source_codec_index_t = int (*)(const uint8_t*);
fn_vendor_source_codec_index_t original_vendor_source_codec_index = nullptr;
int fake_vendor_source_codec_index(const uint8_t* p_codec_info) {
    if (isAppleCodecInfo(p_codec_info)) {
        LOGI("VendorSourceCodecIndex(Apple) -> hijacked slot (=%d)", g_codec_index_hijacked);
        return g_codec_index_hijacked;
    }
    return original_vendor_source_codec_index
               ? original_vendor_source_codec_index(p_codec_info)
               : 0;
}

// 18) A2DP_VendorGetEncoderInterface(const uint8_t* p_codec_info)
//                   -> const tA2DP_ENCODER_INTERFACE*
//     Mid-level dispatcher: takes an A2DP vendor codec info blob and
//     returns a per-codec encoder interface. AOSP matches on a hardcoded
//     (vendor_id, codec_id) table — Opus (0xE0/0x0001), aptX (0x4F/1),
//     LDAC (0x12D/0xAA), etc. Apple (0x4C/0x8001) isn't there, so it
//     returns nullptr. Result: `btif_a2dp_source_setup_codec` errors
//     out with "no source encoder interface" and the stack abandons
//     our software Opus attempt.
//     Fix: recognize Apple IDs here and return the AAC-ELD encoder
//     interface directly, bypassing the missing table entry.
using fn_vendor_get_encoder_iface_t =
    const tA2DP_ENCODER_INTERFACE* (*)(const uint8_t*);
fn_vendor_get_encoder_iface_t original_vendor_get_encoder_iface = nullptr;
const tA2DP_ENCODER_INTERFACE* fake_vendor_get_encoder_iface(
    const uint8_t* p_codec_info) {
    if (isOurCodecInfo(p_codec_info)) {
        LOGI("A2DP_VendorGetEncoderInterface(ours) -> AAC-ELD interface @ %p",
             &g_aaceld_interface);
        return &g_aaceld_interface;
    }
    return original_vendor_get_encoder_iface
               ? original_vendor_get_encoder_iface(p_codec_info)
               : nullptr;
}

// 17) bluetooth::audio::aidl::a2dp::update_codec_offloading_capabilities(
//                       const std::vector<btav_a2dp_codec_config_t>&, bool)
//     The Bluetooth Audio HAL calls this at init to tell the stack
//     "these codecs are offloadable to the DSP". The stack caches the
//     result in a global ProviderInfo, and `setup_codec` later consults
//     the cache inline (bypassing our ProviderInfo::SupportsCodec hook)
//     to decide A2DP_HARDWARE_OFFLOAD_ENCODING_DATAPATH vs
//     A2DP_SOFTWARE_ENCODING_DATAPATH.
//
//     By suppressing this update call (just ret), the cache stays empty
//     (or null). Every subsequent "is this codec offloadable?" check
//     returns false → the stack routes everything through the software
//     encoder path where our AAC-ELD encoder actually runs.
//
//     Collateral damage: AAC/SBC/LDAC offload also disabled. If their
//     software encoders exist and Pixel 10 can drive them, fine. If
//     not, those codecs break until we make this hook selective.
using fn_update_codec_offload_caps_t = void (*)(const void*, bool);
fn_update_codec_offload_caps_t original_update_codec_offload_caps = nullptr;
void fake_update_codec_offload_caps(const void* codecs_vec, bool flag) {
    // Earlier we suppressed this entirely to prevent the stack from
    // caching HAL offload caps — but that broke AAC/SBC too because
    // Pixel 10's BT audio HAL has no software encoder fallback for
    // those codecs. Revert to calling the original so AAC/SBC keep
    // working. Opus will still get offloaded here, but our other hooks
    // (provider::supports_codec, IsCodecOffloadingEnabled) are the
    // intended gatekeeper per-codec.
    LOGI("update_codec_offloading_capabilities(vec=%p, flag=%d) — passing through to original",
         codecs_vec, (int)flag);
    if (original_update_codec_offload_caps) {
        original_update_codec_offload_caps(codecs_vec, flag);
    }
}

// 16) bluetooth::audio::aidl::a2dp::ProviderInfo::SupportsCodec(
//                       btav_a2dp_codec_index_t) const -> bool
//     This is the class member function the stack uses to ask the HAL
//     ProviderInfo "is this codec_index on your offload list?". Two
//     direct callers exist in libbluetooth_jni.so:
//       - 0x694e20  provider::supports_codec wrapper (neg. time)
//       - 0x6947a4  setup_codec direct call (stream-start time)
//     Hooking the wrapper only catches the negotiation path; the
//     setup_codec → direct call at 0x6947a4 bypasses the wrapper. So
//     hook the member function itself at 0x6bfb7c — all paths flow
//     through it. Signature is C++ member:
//         bool SupportsCodec(this_ptr, codec_index)  x0=this, w1=idx
//     We return false only for OPUS (idx 6); everything else goes to
//     the original so AAC/SBC/LDAC offload continue to work normally.
using fn_provider_supports_codec_t = bool (*)(void*, int);
fn_provider_supports_codec_t original_provider_supports_codec = nullptr;
bool fake_provider_supports_codec(void* this_ptr, int codec_index) {
    if (codec_index == g_codec_index_hijacked) {
        LOGI("ProviderInfo::SupportsCodec(this=%p, idx=%d) -> false (software path)",
             this_ptr, codec_index);
        return false;
    }
    return original_provider_supports_codec
               ? original_provider_supports_codec(this_ptr, codec_index)
               : false;
}

// 15) bluetooth::audio::aidl::a2dp::codec::IsCodecOffloadingEnabled(
//                       const CodecConfiguration& codec_config) -> bool
//     Pixel 10's Bluetooth Audio HAL is offload-only: if a codec is in
//     the HAL's offloaded capability list, audio PCM goes straight from
//     AudioFlinger to the DSP, bypassing the software encoder path. The
//     DSP can produce real Opus bits but has no AAC-ELD firmware, so our
//     hijacked Opus slot yields ~0.1 s of unintelligible audio that
//     AirPods reject, triggering BTA_AvReconfig back to AAC.
//     Fix: intercept this check and return false only for
//     CodecType::OPUS so the stack routes Opus through the software
//     encoder interface (where A2DP_VendorGetEncoderInterfaceOpus ->
//     our AAC-ELD encoder actually runs).
//     AIDL CodecConfiguration layout:
//       offset 0 : int32_t codecType   (enum backing int32)
//       offset 4 : int32_t encodedAudioBitrate
//       ...
//     AIDL CodecType::OPUS = 9 (verified in aospxref).
// AIDL CodecType for the hijacked slot, loaded alongside codec index.
//   Opus = 9, aptX = 3, aptX-HD = 4, LDAC = 5, LC3 = 6.
int32_t g_aidl_codec_type_hijacked = 9;  // default: Opus

using fn_is_codec_offloading_enabled_t = bool (*)(const void*);
fn_is_codec_offloading_enabled_t original_is_codec_offloading_enabled = nullptr;
bool fake_is_codec_offloading_enabled(const void* codec_config) {
    if (codec_config) {
        int32_t codec_type = *reinterpret_cast<const int32_t*>(codec_config);
        if (codec_type == g_aidl_codec_type_hijacked) {
            LOGI("IsCodecOffloadingEnabled(aidl_type=%d) -> false (route to software)",
                 codec_type);
            return false;
        }
    }
    return original_is_codec_offloading_enabled
               ? original_is_codec_offloading_enabled(codec_config)
               : false;
}

// 14) A2DP_ParseInfoOpus(tA2DP_OPUS_CIE* p_ie, const uint8_t* p_codec_info, bool is_capability)
//     Validates vendor_id (must equal 0x000000E0) + codec_id (0x0001) and
//     fills tA2DP_OPUS_CIE. Without a hook, Apple SEPs fail here and
//     never make the Selectable list. We feed it a fabricated
//     Opus-shaped blob so it populates p_ie successfully; the actual
//     on-wire bytes returned to AirPods still come from our
//     BuildInfoOpus hook, which emits Apple AAC-ELD.
//     Bitmap byte 0x92 = sampleRate 48000 (0x80) | channelMode STEREO
//     (0x02) | frameSize 20 ms (0x10) — AOSP's typical "good" Opus caps.
using fn_parse_info_opus_t = int (*)(void*, const uint8_t*, bool);
fn_parse_info_opus_t original_parse_info_opus = nullptr;
int fake_parse_info_opus(void* p_ie, const uint8_t* p_codec_info,
                         bool is_capability) {
    if (!isAppleCodecInfo(p_codec_info)) {
        return original_parse_info_opus
                   ? original_parse_info_opus(p_ie, p_codec_info, is_capability)
                   : 0;
    }
    // Substitute an Opus-shaped blob the original ParseInfo accepts so
    // p_ie gets populated; the on-wire bytes returned to AirPods still
    // come from our BuildInfoOpus hook, which emits Apple AAC-ELD.
    LOGI("ParseInfo(Apple) -> substituting Opus blob");
    const uint8_t opus_fake_info[] = {
        0x09,                   // LOSC = 9
        0x00,                   // media_type = audio
        0xFF,                   // non-A2DP vendor
        0xE0, 0x00, 0x00, 0x00, // vendor_id = Google (0x000000E0)
        0x01, 0x00,             // codec_id = Opus (0x0001)
        0x92,                   // sampleRate|channelMode|frameSize
    };
    if (original_parse_info_opus)
        return original_parse_info_opus(p_ie, opus_fake_info, is_capability);
    return 0;  // A2DP_SUCCESS
}

// 19) A2DP_GetPacketTimestamp(const uint8_t* codec_info,
//                             const uint8_t* p_data,
//                             uint32_t* p_timestamp) -> bool
//     Called by BtaAvCo::GetNextSourceDataPacket for every packet our
//     encoder enqueues. The stack maintains a hardcoded whitelist of
//     vendor codec IDs (Opus 0xE0/0x0001, aptX 0x4F/0x0001, aptX-HD
//     0xD7/0x0024, LDAC 0x12D/0x00AA); anything else triggers
//     "unsupported codec id 0x..." and the function returns 0, which
//     causes GetNextSourceDataPacket to osi_free() the BT_HDR and return
//     nullptr. Net result: every AAC-ELD frame we build gets dropped on
//     the floor before AVDTP sees it, even though enqueue_cb returned
//     accepted=1 and everything upstream thinks the stream is healthy.
//
//     Fix: recognize Apple vendor 0x004C + codec 0x8001 and return a
//     monotonically increasing timestamp. The 1440-sample step matches
//     our send_frames default (3 granules * 480 samples = 30 ms at
//     48 kHz). Short-read ticks (1 or 2 granules during buffer underrun)
//     still produce a slightly drifty timestamp but RTP receivers are
//     tolerant of that.
using fn_get_packet_timestamp_t = int (*)(const uint8_t*, const uint8_t*, uint32_t*);
fn_get_packet_timestamp_t original_get_packet_timestamp = nullptr;
int fake_get_packet_timestamp(const uint8_t* p_codec_info,
                               const uint8_t* p_data,
                               uint32_t* p_timestamp) {
    if (isOurCodecInfo(p_codec_info) && p_timestamp && p_data) {
        // enc_send_frames stashed this packet's exact timestamp in the 4
        // bytes immediately before payload start (headroom area). Reading
        // it back here keeps RTP timestamps perfectly aligned with the
        // Apple header sequence numbers — which both reset to known
        // values on feeding_reset, so no drift survives a stream
        // suspend/restart cycle.
        uint32_t ts = (uint32_t)p_data[-4]
                    | ((uint32_t)p_data[-3] <<  8)
                    | ((uint32_t)p_data[-2] << 16)
                    | ((uint32_t)p_data[-1] << 24);
        *p_timestamp = ts;
        return 1;  // success
    }
    return original_get_packet_timestamp
               ? original_get_packet_timestamp(p_codec_info, p_data, p_timestamp)
               : 0;
}

// 20) A2DP_VendorBuildCodecHeader(const uint8_t* codec_info,
//                                  BT_HDR* p_buf,
//                                  uint16_t frames_per_packet) -> bool
//     Same whitelist problem as GetPacketTimestamp: the stack only knows
//     OPUS / APTX / APTX-HD / LDAC. APTX / APTX-HD / Opus all return 1
//     directly without prepending anything (no media payload header
//     required for their RTP format); LDAC tail-calls into its own
//     LdacBuildCodecHeader. AAC-ELD with raw AU transport (TT_MP4_RAW)
//     also requires no prepended header — the Apple 4-byte header is
//     already inside the payload we built in enc_send_frames.
//     Fix: for Apple, return 1 without touching p_buf. Everything else
//     falls through to the original.
using fn_vendor_build_codec_header_t =
    int (*)(const uint8_t*, void* /*BT_HDR*/, uint16_t);
fn_vendor_build_codec_header_t original_vendor_build_codec_header = nullptr;
int fake_vendor_build_codec_header(const uint8_t* p_codec_info,
                                    void* p_buf,
                                    uint16_t frames_per_packet) {
    if (isOurCodecInfo(p_codec_info)) {
        return 1;  // success; no prepend needed for AAC-ELD TT_MP4_RAW
    }
    return original_vendor_build_codec_header
               ? original_vendor_build_codec_header(p_codec_info, p_buf,
                                                      frames_per_packet)
               : 0;
}

// --------------------- install helper ----------------------------------

bool tryHook(HookFunType hook_func, uintptr_t base_addr, uintptr_t offset,
             const char* name, void* replace, void** backup) {
    if (offset == 0) { LOGI("skipping %s (no offset)", name); return false; }
    void* target = reinterpret_cast<void*>(base_addr + offset);
    int rc = hook_func(target, replace, backup);
    if (rc != 0) {
        LOGE("hook %s failed rc=%d (target=%p)", name, rc, target);
        return false;
    }
    LOGI("hooked %s @ %p", name, target);
    return true;
}

}  // namespace

// ---------------- offset loader impls (public) -------------------------

uintptr_t loadBuildInfoOpusOffset()             { return readOffsetProp("persist.librepods.a2dp_build_info_opus_offset"); }
uintptr_t loadCodecTypeEqualsOpusOffset()       { return readOffsetProp("persist.librepods.a2dp_codec_type_equals_opus_offset"); }
uintptr_t loadCodecEqualsOpusOffset()           { return readOffsetProp("persist.librepods.a2dp_codec_equals_opus_offset"); }
uintptr_t loadGetEncoderInterfaceOpusOffset()   { return readOffsetProp("persist.librepods.a2dp_encoder_iface_opus_offset"); }
uintptr_t loadGetTrackSampleRateOpusOffset()    { return readOffsetProp("persist.librepods.a2dp_sample_rate_opus_offset"); }
uintptr_t loadGetTrackChannelCountOpusOffset()  { return readOffsetProp("persist.librepods.a2dp_channel_count_opus_offset"); }
uintptr_t loadGetTrackBitsPerSampleOpusOffset() { return readOffsetProp("persist.librepods.a2dp_bits_per_sample_opus_offset"); }
uintptr_t loadGetBitRateOpusOffset()            { return readOffsetProp("persist.librepods.a2dp_bit_rate_opus_offset"); }
uintptr_t loadGetFrameSizeOpusOffset()          { return readOffsetProp("persist.librepods.a2dp_frame_size_opus_offset"); }
uintptr_t loadGetChannelModeCodeOpusOffset()    { return readOffsetProp("persist.librepods.a2dp_channel_mode_opus_offset"); }
uintptr_t loadIsVendorSourceCodecValidOffset()  { return readOffsetProp("persist.librepods.a2dp_is_vendor_src_valid_offset"); }
uintptr_t loadIsCodecValidOpusOffset()          { return readOffsetProp("persist.librepods.a2dp_is_codec_valid_opus_offset"); }
uintptr_t loadVendorSourceCodecIndexOffset()    { return readOffsetProp("persist.librepods.a2dp_vendor_src_codec_index_offset"); }
uintptr_t loadParseInfoOpusOffset()             { return readOffsetProp("persist.librepods.a2dp_parse_info_opus_offset"); }
uintptr_t loadIsCodecOffloadingEnabledOffset()  { return readOffsetProp("persist.librepods.a2dp_is_codec_offloading_enabled_offset"); }
uintptr_t loadProviderSupportsCodecOffset()     { return readOffsetProp("persist.librepods.a2dp_provider_supports_codec_offset"); }
uintptr_t loadUpdateCodecOffloadingCapsOffset() { return readOffsetProp("persist.librepods.a2dp_update_codec_offload_caps_offset"); }
uintptr_t loadVendorGetEncoderInterfaceOffset() { return readOffsetProp("persist.librepods.a2dp_vendor_get_encoder_iface_offset"); }
uintptr_t loadGetPacketTimestampOffset()        { return readOffsetProp("persist.librepods.a2dp_get_packet_timestamp_offset"); }
uintptr_t loadVendorBuildCodecHeaderOffset()    { return readOffsetProp("persist.librepods.a2dp_vendor_build_codec_header_offset"); }

// ---------------- public entrypoint ------------------------------------

bool installA2dpHooks(const char* library_name, HookFunType hook_func) {
    if (!hook_func) { LOGE("hook_func is null"); return false; }

    uintptr_t base_addr = getModuleBase(library_name);
    if (!base_addr) {
        LOGE("failed to locate base of %s", library_name);
        return false;
    }
    LOGI("installing AAC-ELD hooks (Opus slot %d, AIDL type %d) base=%s 0x%lx",
         g_codec_index_hijacked, g_aidl_codec_type_hijacked,
         library_name, (unsigned long)base_addr);

    // FDK-AAC is already statically linked into libbluetooth_jni.so; bind
    // via offsets before any hook can reach the encoder.
    if (!resolveFdkSymbols(base_addr)) {
        LOGE("cannot bind FDK-AAC symbols; aborting A2DP hooks");
        return false;
    }

    bool any = false;
    any |= tryHook(hook_func, base_addr, loadBuildInfoOpusOffset(),
                   "BuildInfoOpus",
                   (void*)fake_build_info_opus,
                   (void**)&original_build_info_opus);
    any |= tryHook(hook_func, base_addr, loadCodecTypeEqualsOpusOffset(),
                   "VendorCodecTypeEqualsOpus",
                   (void*)fake_codec_type_equals_opus,
                   (void**)&original_codec_type_equals_opus);
    any |= tryHook(hook_func, base_addr, loadCodecEqualsOpusOffset(),
                   "VendorCodecEqualsOpus",
                   (void*)fake_codec_equals_opus,
                   (void**)&original_codec_equals_opus);
    any |= tryHook(hook_func, base_addr, loadGetEncoderInterfaceOpusOffset(),
                   "VendorGetEncoderInterfaceOpus",
                   (void*)fake_get_encoder_iface_opus,
                   (void**)&original_get_encoder_iface_opus);
    any |= tryHook(hook_func, base_addr, loadGetTrackSampleRateOpusOffset(),
                   "VendorGetTrackSampleRateOpus",
                   (void*)fake_get_sample_rate_opus,
                   (void**)&original_get_sample_rate_opus);
    any |= tryHook(hook_func, base_addr, loadGetTrackChannelCountOpusOffset(),
                   "VendorGetTrackChannelCountOpus",
                   (void*)fake_get_channel_count_opus,
                   (void**)&original_get_channel_count_opus);
    any |= tryHook(hook_func, base_addr, loadGetTrackBitsPerSampleOpusOffset(),
                   "VendorGetTrackBitsPerSampleOpus",
                   (void*)fake_get_bits_per_sample_opus,
                   (void**)&original_get_bits_per_sample_opus);
    any |= tryHook(hook_func, base_addr, loadGetBitRateOpusOffset(),
                   "VendorGetBitRateOpus",
                   (void*)fake_get_bit_rate_opus,
                   (void**)&original_get_bit_rate_opus);
    any |= tryHook(hook_func, base_addr, loadGetFrameSizeOpusOffset(),
                   "VendorGetFrameSizeOpus",
                   (void*)fake_get_frame_size_opus,
                   (void**)&original_get_frame_size_opus);
    any |= tryHook(hook_func, base_addr, loadGetChannelModeCodeOpusOffset(),
                   "VendorGetChannelModeCodeOpus",
                   (void*)fake_get_channel_mode_opus,
                   (void**)&original_get_channel_mode_opus);
    any |= tryHook(hook_func, base_addr, loadIsVendorSourceCodecValidOffset(),
                   "IsVendorSourceCodecValid",
                   (void*)fake_is_vendor_src_valid,
                   (void**)&original_is_vendor_src_valid);
    any |= tryHook(hook_func, base_addr, loadIsCodecValidOpusOffset(),
                   "IsCodecValidOpus",
                   (void*)fake_is_codec_valid_opus,
                   (void**)&original_is_codec_valid_opus);
    any |= tryHook(hook_func, base_addr, loadVendorSourceCodecIndexOffset(),
                   "VendorSourceCodecIndex",
                   (void*)fake_vendor_source_codec_index,
                   (void**)&original_vendor_source_codec_index);
    any |= tryHook(hook_func, base_addr, loadParseInfoOpusOffset(),
                   "ParseInfoOpus",
                   (void*)fake_parse_info_opus,
                   (void**)&original_parse_info_opus);
    any |= tryHook(hook_func, base_addr, loadIsCodecOffloadingEnabledOffset(),
                   "IsCodecOffloadingEnabled",
                   (void*)fake_is_codec_offloading_enabled,
                   (void**)&original_is_codec_offloading_enabled);
    any |= tryHook(hook_func, base_addr, loadProviderSupportsCodecOffset(),
                   "provider::supports_codec",
                   (void*)fake_provider_supports_codec,
                   (void**)&original_provider_supports_codec);
    any |= tryHook(hook_func, base_addr, loadUpdateCodecOffloadingCapsOffset(),
                   "update_codec_offloading_capabilities",
                   (void*)fake_update_codec_offload_caps,
                   (void**)&original_update_codec_offload_caps);
    any |= tryHook(hook_func, base_addr, loadVendorGetEncoderInterfaceOffset(),
                   "A2DP_VendorGetEncoderInterface",
                   (void*)fake_vendor_get_encoder_iface,
                   (void**)&original_vendor_get_encoder_iface);
    // Tx-path gatekeepers: without these two, every encoded packet we
    // enqueue is correctly built and sized, but dropped at send time
    // because the stack's vendor-codec whitelist doesn't recognize
    // Apple 0x004C/0x8001. Symptom without them: "enc_send_frames"
    // logs every 30 ms but AirPods play silence.
    any |= tryHook(hook_func, base_addr, loadGetPacketTimestampOffset(),
                   "A2DP_GetPacketTimestamp",
                   (void*)fake_get_packet_timestamp,
                   (void**)&original_get_packet_timestamp);
    any |= tryHook(hook_func, base_addr, loadVendorBuildCodecHeaderOffset(),
                   "A2DP_VendorBuildCodecHeader",
                   (void*)fake_vendor_build_codec_header,
                   (void**)&original_vendor_build_codec_header);

    if (!any) {
        LOGW("no AAC-ELD hooks installed - set persist.librepods.a2dp_* props");
    }
    return any;
}

}  // namespace librepods::aaceld
