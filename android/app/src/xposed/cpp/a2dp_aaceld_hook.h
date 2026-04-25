/*
    LibrePods - AirPods liberated from Apple's ecosystem
    Copyright (C) 2025 LibrePods contributors

    Apple AAC-ELD (vendor codec 0x004C / 0x8001) injected into Android's
    A2DP source path by HIJACKING the Opus codec slot. The Android stack
    keeps calling the Opus-family helpers, but our hooks make each helper
    return values that describe Apple's codec instead, and our encoder
    interface replaces the Opus encoder end-to-end.

    Why Opus: on Android 16 (Pixel 10 libbluetooth_jni.so) every Opus
    helper symbol is exported individually, whereas AptX / LDAC / AAC are
    part of active codec selection the user may actually care about. A2DP
    Opus is rarely supported by sinks in practice, so hijacking it is the
    lowest-impact way to get a working source-side AAC-ELD without
    growing the codec_index enum (which would require touching
    A2dpCodecs::init).

    All offsets are optional and loaded from persist.librepods.a2dp_*
    properties; a missing offset simply skips that hook. Symbol names
    come from rabin2 -qE output on the real device binary.
*/

#pragma once

#include <cstdint>

#include "l2c_fcr_hook.h"  // HookFunType

namespace librepods::aaceld {

// One-shot installer, called from on_library_loaded() once libbluetooth_jni.so
// has been resolved in the Bluetooth process.
bool installA2dpHooks(const char* library_name, HookFunType hook_func);

// Individual offset loaders. Every loader returns 0 if the corresponding
// persist.librepods.a2dp_<name>_offset property is missing or malformed,
// and the matching hook is silently skipped. See root-module/customize.sh
// for the symbol->property mapping published at install time.
uintptr_t loadBuildInfoOpusOffset();           // A2DP_BuildInfoOpus
uintptr_t loadCodecTypeEqualsOpusOffset();     // A2DP_VendorCodecTypeEqualsOpus
uintptr_t loadCodecEqualsOpusOffset();         // A2DP_VendorCodecEqualsOpus
uintptr_t loadGetEncoderInterfaceOpusOffset(); // A2DP_VendorGetEncoderInterfaceOpus
uintptr_t loadGetTrackSampleRateOpusOffset();  // A2DP_VendorGetTrackSampleRateOpus
uintptr_t loadGetTrackChannelCountOpusOffset();// A2DP_VendorGetTrackChannelCountOpus
uintptr_t loadGetTrackBitsPerSampleOpusOffset();// A2DP_VendorGetTrackBitsPerSampleOpus
uintptr_t loadGetBitRateOpusOffset();          // A2DP_VendorGetBitRateOpus
uintptr_t loadGetFrameSizeOpusOffset();        // A2DP_VendorGetFrameSizeOpus
uintptr_t loadGetChannelModeCodeOpusOffset();  // A2DP_VendorGetChannelModeCodeOpus
uintptr_t loadIsVendorSourceCodecValidOffset();// A2DP_IsVendorSourceCodecValid
uintptr_t loadIsCodecValidOpusOffset();        // A2DP_IsCodecValidOpus
uintptr_t loadVendorSourceCodecIndexOffset();  // A2DP_VendorSourceCodecIndex
uintptr_t loadParseInfoOpusOffset();           // A2DP_ParseInfoOpus
uintptr_t loadIsCodecOffloadingEnabledOffset();// IsCodecOffloadingEnabled (AIDL a2dp codec)
uintptr_t loadProviderSupportsCodecOffset();   // bluetooth::audio::aidl::a2dp::provider::supports_codec
uintptr_t loadUpdateCodecOffloadingCapsOffset();// update_codec_offloading_capabilities
uintptr_t loadVendorGetEncoderInterfaceOffset();// A2DP_VendorGetEncoderInterface (mid-dispatcher)
// The following two are required for packets to actually hit the wire. Without
// them, every frame we enqueue is correctly encoded but dropped in
// BtaAvCo::GetNextSourceDataPacket because the stack's vendor-codec whitelist
// only recognizes OPUS/APTX/APTX-HD/LDAC — Apple's 0x004C/0x8001 tuple falls
// through and both helpers return 0, which is treated as "unsupported codec".
uintptr_t loadGetPacketTimestampOffset();       // A2DP_GetPacketTimestamp
uintptr_t loadVendorBuildCodecHeaderOffset();   // A2DP_VendorBuildCodecHeader

}  // namespace librepods::aaceld
