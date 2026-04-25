/*
    LibrePods - AirPods liberated from Apple's ecosystem
    Copyright (C) 2025 LibrePods contributors

    FDK-AAC wrapper that resolves the encoder entrypoints at runtime from
    libbluetooth_jni.so (which already statically links FDK for the
    standard A2DP AAC path). ABI types are reproduced inline from
    FDK-AAC's aacenc_lib.h — they have been stable since ~2012.
*/

#include "aaceld_encoder.h"

#include <android/log.h>
#include <sys/system_properties.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

#define LOG_TAG "AirPodsHook.AACELD"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace librepods::aaceld {

// ---------- FDK-AAC ABI (inlined from aacenc_lib.h) --------------------

namespace fdk {

using AACENCODER = void;
enum AACENC_ERROR : int { AACENC_OK = 0 };

// Values from libfdk-aac aacenc_lib.h (stable since 2012). Confirmed by
// on-device "aacEncoder_SetParam(…) failed" log: the shipped encoder
// rejects 0x0109 / 0x0201, accepts 0x0105 / 0x0300.
enum AACENC_PARAM : int {
    AACENC_AOT            = 0x0100,
    AACENC_BITRATE        = 0x0101,
    AACENC_BITRATEMODE    = 0x0102,
    AACENC_SAMPLERATE     = 0x0103,
    AACENC_SBR_MODE       = 0x0104,
    AACENC_GRANULE_LENGTH = 0x0105,
    AACENC_CHANNELMODE    = 0x0106,
    AACENC_AFTERBURNER    = 0x0200,
    AACENC_TRANSMUX       = 0x0300,
};

// Buffer identifiers. Values from aacenc_lib.h TRANSPORT_TYPE + buf IDs.
enum : int {
    IN_AUDIO_DATA     = 0,
    OUT_BITSTREAM_DATA = 3,
};

// Transport types. TT_MP4_RAW = 0 (raw access units, no framing).
enum : int { TT_MP4_RAW = 0 };

struct AACENC_BufDesc {
    int numBufs;
    void** bufs;
    int* bufferIdentifiers;
    int* bufSizes;
    int* bufElSizes;
};

struct AACENC_InArgs {
    int numInSamples;
    int numAncBytes;
};

struct AACENC_OutArgs {
    int numOutBytes;
    int numInSamples;
    int numAncBytes;
    int bitResState;
};

struct AACENC_InfoStruct {
    unsigned int maxOutBufBytes;
    unsigned int maxAncBytes;
    unsigned int inBufFillLevel;
    unsigned int inputChannels;
    unsigned int frameLength;
    unsigned int nDelay;
    unsigned int nDelayCore;
    // Remaining fields (confBuf, confSize) are not needed; the struct
    // is only read up to nDelayCore so trailing layout doesn't matter.
    unsigned char _pad[256];
};

using aacEncOpen_t        = AACENC_ERROR (*)(AACENCODER**, unsigned, unsigned);
using aacEncClose_t       = AACENC_ERROR (*)(AACENCODER**);
using aacEncEncode_t      = AACENC_ERROR (*)(const AACENCODER*, const AACENC_BufDesc*,
                                             const AACENC_BufDesc*, const AACENC_InArgs*,
                                             AACENC_OutArgs*);
using aacEncoder_SetParam_t = AACENC_ERROR (*)(AACENCODER*, AACENC_PARAM, unsigned);
using aacEncInfo_t        = AACENC_ERROR (*)(const AACENCODER*, AACENC_InfoStruct*);

struct Bind {
    aacEncOpen_t          Open = nullptr;
    aacEncClose_t         Close = nullptr;
    aacEncEncode_t        Encode = nullptr;
    aacEncoder_SetParam_t SetParam = nullptr;
    aacEncInfo_t          Info = nullptr;

    bool complete() const {
        return Open && Close && Encode && SetParam && Info;
    }
};

static Bind g_bind;

}  // namespace fdk

// ---------- offset loader ----------------------------------------------

namespace {

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
        return offset;
    }
    return 0;
}

template <typename Fn>
bool bindOne(uintptr_t base, const char* prop, const char* name, Fn* out) {
    uintptr_t off = readOffsetProp(prop);
    if (off == 0) { LOGE("FDK: no offset for %s (%s)", name, prop); return false; }
    *out = reinterpret_cast<Fn>(base + off);
    LOGI("FDK: %-22s = %p", name, (void*)*out);
    return true;
}

}  // namespace

bool resolveFdkSymbols(uintptr_t base) {
    if (!base) { LOGE("FDK: null libbluetooth_jni.so base"); return false; }
    bool ok = true;
    ok &= bindOne(base, "persist.librepods.fdk_enc_open_offset",
                  "aacEncOpen", &fdk::g_bind.Open);
    ok &= bindOne(base, "persist.librepods.fdk_enc_close_offset",
                  "aacEncClose", &fdk::g_bind.Close);
    ok &= bindOne(base, "persist.librepods.fdk_enc_encode_offset",
                  "aacEncEncode", &fdk::g_bind.Encode);
    ok &= bindOne(base, "persist.librepods.fdk_enc_setparam_offset",
                  "aacEncoder_SetParam", &fdk::g_bind.SetParam);
    ok &= bindOne(base, "persist.librepods.fdk_enc_info_offset",
                  "aacEncInfo", &fdk::g_bind.Info);
    if (!ok) { fdk::g_bind = fdk::Bind{}; return false; }
    LOGI("FDK-AAC bound to libbluetooth_jni.so @ 0x%lx", (unsigned long)base);
    return true;
}

bool fdkResolved() { return fdk::g_bind.complete(); }

// ---------- Encoder ----------------------------------------------------

Encoder::Encoder() = default;

Encoder::~Encoder() { close(); }

bool Encoder::init(const EncoderConfig& cfg) {
    cfg_ = cfg;
    if (!fdk::g_bind.complete()) {
        LOGE("FDK not resolved; call resolveFdkSymbols() first");
        return false;
    }
    if (initialized_) close();

    fdk::AACENCODER* enc = nullptr;
    if (fdk::g_bind.Open(&enc, 0x01 /* default modules */, cfg_.channels) != fdk::AACENC_OK) {
        LOGE("aacEncOpen failed");
        return false;
    }

    auto set = [&](fdk::AACENC_PARAM param, unsigned value, const char* name) -> bool {
        if (fdk::g_bind.SetParam(enc, param, value) != fdk::AACENC_OK) {
            LOGE("aacEncoder_SetParam(%s=%u) failed", name, value);
            return false;
        }
        return true;
    };

    bool ok = true;
    ok &= set(fdk::AACENC_AOT,            39,                     "AOT=ER_AAC_ELD");
    ok &= set(fdk::AACENC_BITRATE,        cfg_.bitrate,           "BITRATE");
    ok &= set(fdk::AACENC_SAMPLERATE,     cfg_.sample_rate,       "SAMPLERATE");
    ok &= set(fdk::AACENC_CHANNELMODE,    cfg_.channels,          "CHANNELMODE");
    ok &= set(fdk::AACENC_GRANULE_LENGTH, cfg_.granule_length,    "GRANULE_LENGTH");
    ok &= set(fdk::AACENC_SBR_MODE,       cfg_.sbr_enabled ? 1 : 0, "SBR_MODE");
    ok &= set(fdk::AACENC_BITRATEMODE,    0,                      "BITRATEMODE=CBR");
    ok &= set(fdk::AACENC_AFTERBURNER,    0,                      "AFTERBURNER=off");
    ok &= set(fdk::AACENC_TRANSMUX,       fdk::TT_MP4_RAW,        "TRANSMUX=raw");

    if (!ok) {
        fdk::g_bind.Close(&enc);
        return false;
    }

    // Drive FDK to finalize internal state before feeding real audio.
    if (fdk::g_bind.Encode(enc, nullptr, nullptr, nullptr, nullptr) != fdk::AACENC_OK) {
        LOGE("aacEncEncode(init) failed");
        fdk::g_bind.Close(&enc);
        return false;
    }

    // Verify the encoder actually applied our parameters.
    fdk::AACENC_InfoStruct info{};
    if (fdk::g_bind.Info(enc, &info) != fdk::AACENC_OK) {
        LOGE("aacEncInfo failed");
        fdk::g_bind.Close(&enc);
        return false;
    }

    LOGI("FDK aacEncInfo: frameLength=%u inputChannels=%u maxOutBufBytes=%u "
         "nDelay=%u nDelayCore=%u",
         info.frameLength, info.inputChannels, info.maxOutBufBytes,
         info.nDelay, info.nDelayCore);

    if (info.frameLength != cfg_.granule_length) {
        LOGE("GRANULE MISMATCH: requested %u but encoder reports frameLength=%u",
             cfg_.granule_length, info.frameLength);
    }
    if (info.inputChannels != cfg_.channels) {
        LOGE("CHANNEL MISMATCH: requested %u but encoder reports inputChannels=%u",
             cfg_.channels, info.inputChannels);
    }

    actual_frame_length_ = info.frameLength;
    actual_input_channels_ = info.inputChannels;
    max_out_buf_bytes_ = info.maxOutBufBytes;

    aac_handle_ = enc;
    frame_sequence_ = 1;
    initialized_ = true;
    LOGI("AAC-ELD encoder ready: %u Hz / %u ch / %u bps / granule=%u(actual=%u) / SBR=%d",
         cfg_.sample_rate, cfg_.channels, cfg_.bitrate,
         cfg_.granule_length, actual_frame_length_, (int)cfg_.sbr_enabled);
    return true;
}

void Encoder::close() {
    if (aac_handle_ && fdk::g_bind.Close) {
        auto* enc = reinterpret_cast<fdk::AACENCODER*>(aac_handle_);
        fdk::g_bind.Close(&enc);
        aac_handle_ = nullptr;
    }
    initialized_ = false;
}

bool Encoder::reset() {
    EncoderConfig cfg = cfg_;
    close();
    frame_sequence_ = 1;
    return init(cfg);
}

size_t Encoder::encodeFrame(const int16_t* pcm_in, size_t pcm_samples,
                            uint8_t* au_out, size_t au_cap) {
    if (!initialized_ || !pcm_in || !au_out) return 0;
    if (!fdk::g_bind.Encode) return 0;

    auto* enc = reinterpret_cast<fdk::AACENCODER*>(aac_handle_);

    void* in_bufs[1] = { const_cast<int16_t*>(pcm_in) };
    int in_ids[1] = { fdk::IN_AUDIO_DATA };
    int in_sizes[1] = { (int)(pcm_samples * sizeof(int16_t)) };
    int in_el_sizes[1] = { (int)sizeof(int16_t) };
    fdk::AACENC_BufDesc in_desc = {
        .numBufs = 1,
        .bufs = in_bufs,
        .bufferIdentifiers = in_ids,
        .bufSizes = in_sizes,
        .bufElSizes = in_el_sizes,
    };

    void* out_bufs[1] = { au_out };
    int out_ids[1] = { fdk::OUT_BITSTREAM_DATA };
    int out_sizes[1] = { (int)au_cap };
    int out_el_sizes[1] = { 1 };
    fdk::AACENC_BufDesc out_desc = {
        .numBufs = 1,
        .bufs = out_bufs,
        .bufferIdentifiers = out_ids,
        .bufSizes = out_sizes,
        .bufElSizes = out_el_sizes,
    };

    fdk::AACENC_InArgs in_args = {
        .numInSamples = (int)pcm_samples,
        .numAncBytes = 0,
    };
    fdk::AACENC_OutArgs out_args = {};

    auto err = fdk::g_bind.Encode(enc, &in_desc, &out_desc, &in_args, &out_args);
    if (err != fdk::AACENC_OK) {
        LOGE("aacEncEncode err=0x%x", (unsigned)err);
        return 0;
    }
    return (size_t)out_args.numOutBytes;
}

bool Encoder::buildFrameHeader(uint32_t au_size, AppleFrameHeader* out) {
    if (!out) return false;
    if (au_size > kMaxAuSize) {
        LOGE("AU size %u exceeds Apple header max 0x7FF", au_size);
        return false;
    }
    const uint32_t seq = frame_sequence_ & kSequenceMask;
    out->b0 = (uint8_t)(0xB0 | ((seq >> 8) & 0x0F));
    out->b1 = (uint8_t)(seq & 0xFF);
    out->b2 = (uint8_t)(0x10 | ((au_size >> 8) & 0x0F));
    out->b3 = (uint8_t)(au_size & 0xFF);
    frame_sequence_ = (frame_sequence_ + 1) & kSequenceMask;
    if (frame_sequence_ == 0) frame_sequence_ = 1;
    return true;
}

size_t Encoder::packRtpPayload(const uint8_t* aus, const uint16_t* au_sizes,
                               size_t frame_count,
                               uint8_t* rtp_payload_out, size_t rtp_payload_cap) {
    if (!aus || !au_sizes || !rtp_payload_out) return 0;

    size_t written = 0;
    size_t read = 0;
    for (size_t i = 0; i < frame_count; ++i) {
        const uint16_t sz = au_sizes[i];
        if (written + kAppleHeaderBytes + sz > rtp_payload_cap) {
            LOGE("RTP payload buffer too small for frame %zu", i);
            return 0;
        }
        AppleFrameHeader hdr{};
        if (!buildFrameHeader(sz, &hdr)) return 0;
        std::memcpy(rtp_payload_out + written, &hdr, kAppleHeaderBytes);
        written += kAppleHeaderBytes;
        std::memcpy(rtp_payload_out + written, aus + read, sz);
        written += sz;
        read += sz;
    }
    return written;
}

void Encoder::resetSequence() { frame_sequence_ = 1; }

}  // namespace librepods::aaceld
