/*
    LibrePods - AirPods liberated from Apple’s ecosystem
    Copyright (C) 2025 LibrePods contributors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package me.kavishdevar.librepods.presentation.screens

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import kotlinx.coroutines.launch
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.net.toUri
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.kyant.backdrop.backdrops.layerBackdrop
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import dev.chrisbanes.haze.hazeSource
import me.kavishdevar.librepods.BuildConfig
import me.kavishdevar.librepods.R
import me.kavishdevar.librepods.presentation.components.DeviceInfoCard
import me.kavishdevar.librepods.presentation.components.NavigationButton
import me.kavishdevar.librepods.presentation.components.StyledButton
import me.kavishdevar.librepods.presentation.components.StyledScaffold
import me.kavishdevar.librepods.presentation.components.StyledSlider
import me.kavishdevar.librepods.presentation.components.StyledToggle
import me.kavishdevar.librepods.presentation.viewmodel.AppSettingsViewModel

@Composable
fun AppSettingsScreen(
    navController: NavController, viewModel: AppSettingsViewModel = viewModel()
) {
    val context = LocalContext.current
    val scrollState = rememberScrollState()
    val state by viewModel.uiState.collectAsState()

    val backdrop = rememberLayerBackdrop()

    StyledScaffold(
        title = stringResource(R.string.settings)
    ) { topPadding, hazeState, bottomPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .layerBackdrop(backdrop)
                .hazeSource(state = hazeState)
                .verticalScroll(scrollState)
                .padding(horizontal = 16.dp)
        ) {
            Spacer(modifier = Modifier.height(topPadding))

            val isDarkTheme = isSystemInDarkTheme()
            val backgroundColor = if (isDarkTheme) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
            val textColor = if (isDarkTheme) Color.White else Color.Black

            if (!state.isPremium && state.connectionSuccessful) {
                StyledButton(
                    onClick = {
                        navController.navigate("purchase_screen")
                    },
                    backdrop = rememberLayerBackdrop(),
                    modifier = Modifier.fillMaxWidth(),
                    maxScale = 0.05f,
                    surfaceColor = if (isSystemInDarkTheme()) Color(0xFF916100) else Color(0xFFE59900)
                ) {
                    Text(
                        stringResource(R.string.unlock_advanced_features),
                        style = TextStyle(
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            fontFamily = FontFamily(Font(R.font.sf_pro)),
                            color = Color.White
                        ),
                    )
                }
            }

            if (state.connectionSuccessful) {
                StyledToggle(
                    title = stringResource(R.string.widget),
                    label = stringResource(R.string.show_phone_battery_in_widget),
                    description = stringResource(R.string.show_phone_battery_in_widget_description),
                    checked = state.showPhoneBatteryInWidget,
                    onCheckedChange = viewModel::setShowPhoneBatteryInWidget,
                    enabled = state.isPremium
                )

                Text(
                    text = stringResource(R.string.conversational_awareness), style = TextStyle(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = textColor.copy(alpha = 0.6f),
                        fontFamily = FontFamily(Font(R.font.sf_pro))
                    ), modifier = Modifier.padding(16.dp, bottom = 2.dp, top = 24.dp)
                )

                Spacer(modifier = Modifier.height(2.dp))

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            backgroundColor, RoundedCornerShape(28.dp)
                        )
                        .padding(vertical = 4.dp)
                ) {
                    StyledToggle(
                        label = stringResource(R.string.conversational_awareness_pause_music),
                        description = stringResource(R.string.conversational_awareness_pause_music_description),
                        checked = state.conversationalAwarenessPauseMusicEnabled,
                        onCheckedChange = viewModel::setConversationalAwarenessPauseMusicEnabled,
                        independent = false,
                        enabled = state.isPremium
                    )

                    HorizontalDivider(
                        thickness = 1.dp,
                        color = Color(0x40888888),
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )

                    StyledToggle(
                        label = stringResource(R.string.relative_conversational_awareness_volume),
                        description = stringResource(R.string.relative_conversational_awareness_volume_description),
                        checked = state.relativeConversationalAwarenessVolumeEnabled,
                        onCheckedChange = viewModel::setRelativeConversationalAwarenessVolumeEnabled,
                        independent = false,
                        enabled = state.isPremium,
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                val conversationalAwarenessVolume = state.conversationalAwarenessVolume
                LaunchedEffect(conversationalAwarenessVolume) {
                    viewModel.setConversationalAwarenessVolume(conversationalAwarenessVolume)
                }

                StyledSlider(
                    label = stringResource(R.string.conversational_awareness_volume),
                    value = conversationalAwarenessVolume,
                    valueRange = 10f..85f,
                    snapPoints = listOf(44f),
                    startLabel = "10%",
                    endLabel = "85%",
                    onValueChange = { newValue ->
                        viewModel.setConversationalAwarenessVolume(
                            newValue
                        )
                    },
                    independent = true,
                    enabled = state.isPremium
                )

//            if (!BuildConfig.PLAY_BUILD) {
//                Spacer(modifier = Modifier.height(16.dp))
//
//                NavigationButton(
//                    to = "",
//                    title = stringResource(R.string.camera_control),
//                    name = stringResource(R.string.set_custom_camera_package),
//                    navController = navController,
//                    onClick = {
//                        if (state.isPremium) viewModel.setShowCameraDialog(true)
//                    },
//                    independent = true,
//                    description = stringResource(R.string.camera_control_app_description)
//                )
//            }

                Spacer(modifier = Modifier.height(16.dp))
                if (context.checkSelfPermission("android.permission.BLUETOOTH_PRIVILEGED") == PackageManager.PERMISSION_GRANTED) {
                    StyledToggle(
                        title = stringResource(R.string.ear_detection),
                        label = stringResource(R.string.disconnect_when_not_wearing),
                        description = stringResource(R.string.disconnect_when_not_wearing_description),
                        checked = state.disconnectWhenNotWearing,
                        onCheckedChange = viewModel::setDisconnectWhenNotWearing,
                        enabled = state.isPremium
                    )
                }

                Text(
                    text = stringResource(R.string.takeover_airpods_state), style = TextStyle(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = textColor.copy(alpha = 0.6f),
                        fontFamily = FontFamily(Font(R.font.sf_pro))
                    ), modifier = Modifier.padding(16.dp, bottom = 2.dp, top = 24.dp)
                )

                Spacer(modifier = Modifier.height(4.dp))

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            backgroundColor, RoundedCornerShape(28.dp)
                        )
                        .padding(vertical = 4.dp)
                ) {
                    StyledToggle(
                        label = stringResource(R.string.takeover_disconnected),
                        description = stringResource(R.string.takeover_disconnected_desc),
                        checked = state.takeoverWhenDisconnected,
                        onCheckedChange = viewModel::setTakeoverWhenDisconnected,
                        independent = false,
                        enabled = state.isPremium
                    )
                    HorizontalDivider(
                        thickness = 1.dp,
                        color = Color(0x40888888),
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )

                    StyledToggle(
                        label = stringResource(R.string.takeover_idle),
                        description = stringResource(R.string.takeover_idle_desc),
                        checked = state.takeoverWhenIdle,
                        onCheckedChange = viewModel::setTakeoverWhenIdle,
                        independent = false,
                        enabled = state.isPremium
                    )
                    HorizontalDivider(
                        thickness = 1.dp,
                        color = Color(0x40888888),
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )

                    StyledToggle(
                        label = stringResource(R.string.takeover_music),
                        description = stringResource(R.string.takeover_music_desc),
                        checked = state.takeoverWhenMusic,
                        onCheckedChange = viewModel::setTakeoverWhenMusic,
                        independent = false,
                        enabled = state.isPremium
                    )
                    HorizontalDivider(
                        thickness = 1.dp,
                        color = Color(0x40888888),
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )

                    StyledToggle(
                        label = stringResource(R.string.takeover_call),
                        description = stringResource(R.string.takeover_call_desc),
                        checked = state.takeoverWhenCall,
                        onCheckedChange = viewModel::setTakeoverWhenCall,
                        independent = false,
                        enabled = state.isPremium
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = stringResource(R.string.takeover_phone_state), style = TextStyle(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = textColor.copy(alpha = 0.6f),
                        fontFamily = FontFamily(Font(R.font.sf_pro))
                    ), modifier = Modifier.padding(horizontal = 16.dp)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            backgroundColor, RoundedCornerShape(28.dp)
                        )
                        .padding(vertical = 4.dp)
                ) {
                    StyledToggle(
                        label = stringResource(R.string.takeover_ringing_call),
                        description = stringResource(R.string.takeover_ringing_call_desc),
                        checked = state.takeoverWhenRingingCall,
                        onCheckedChange = viewModel::setTakeoverWhenRingingCall,
                        independent = false,
                        enabled = state.isPremium
                    )
                    HorizontalDivider(
                        thickness = 1.dp,
                        color = Color(0x40888888),
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )

                    StyledToggle(
                        label = stringResource(R.string.takeover_media_start),
                        description = stringResource(R.string.takeover_media_start_desc),
                        checked = state.takeoverWhenMediaStart,
                        onCheckedChange = viewModel::setTakeoverWhenMediaStart,
                        independent = false,
                        enabled = state.isPremium
                    )
                }

                Text(
                    text = stringResource(R.string.advanced_options), style = TextStyle(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = textColor.copy(alpha = 0.6f),
                        fontFamily = FontFamily(Font(R.font.sf_pro))
                    ), modifier = Modifier.padding(16.dp, bottom = 2.dp, top = 24.dp)
                )

                Spacer(modifier = Modifier.height(2.dp))

                StyledToggle(
                    label = stringResource(R.string.use_alternate_head_tracking_packets),
                    description = stringResource(R.string.use_alternate_head_tracking_packets_description),
                    checked = state.useAlternateHeadTrackingPackets,
                    onCheckedChange = viewModel::setUseAlternateHeadTrackingPackets,
                    independent = true,
                    enabled = state.isPremium
                )
            } else {
                Text(
                    text = stringResource(R.string.customizations_unavailable),
                    style = TextStyle(
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Normal,
                        fontFamily = FontFamily(Font(R.font.sf_pro)),
                        color = textColor.copy(alpha = 0.6f),
                    ),
                    modifier = Modifier
                        .padding(horizontal = 16.dp)
                        .padding(top = 16.dp)
                )
            }


            if (BuildConfig.FLAVOR == "xposed") {
                Spacer(modifier = Modifier.height(16.dp))
                val restartBluetoothText =
                    stringResource(R.string.found_offset_restart_bluetooth)
                StyledToggle(
                    label = stringResource(R.string.act_as_an_apple_device) + " (${
                        stringResource(
                            R.string.requires_xposed
                        )
                    })",
                    description = stringResource(R.string.act_as_an_apple_device_description),
                    checked = state.vendorIdHook,
                    onCheckedChange = { enabled ->
                        Toast.makeText(context, restartBluetoothText, Toast.LENGTH_SHORT).show()
                        viewModel.setVendorIdHook(enabled)
                    },
                    independent = true,
                    enabled = state.isPremium
                )

                // ---- AAC-ELD A2DP codec hijack ------------------------------
                // Drives `enable_aac_eld`: scans libbluetooth_jni.so via
                // rabin2 to publish persist.librepods.a2dp_*_offset and
                // persist.librepods.fdk_*_offset, then restarts the BT
                // stack so the new offsets are picked up by the next load.
                // Disabling clears the props (hooks become no-ops) and
                // restarts BT again. Wrapped in xposed flavor only — the
                // play build doesn't ship the native hook library.
                Spacer(modifier = Modifier.height(16.dp))
                val isProcessingAaceld = remember { mutableStateOf(false) }
                val enableAaceld = remember {
                    mutableStateOf(me.kavishdevar.librepods.utils.RadareOffsetFinder
                        .isA2dpAaceldOffsetAvailable())
                }
                val aaceldNotFoundText = stringResource(R.string.aac_eld_offsets_not_found)
                val aaceldDisabledText = stringResource(R.string.aac_eld_disabled)
                val aaceldEnablingTitle = stringResource(R.string.aac_eld_enabling_title)
                val aaceldEnablingMessage = stringResource(R.string.aac_eld_enabling_message)
                val aaceldSuccessTitle = stringResource(R.string.aac_eld_success_title)
                val aaceldSuccessMessage = stringResource(R.string.aac_eld_success_message)
                val aaceldSuccessOk = stringResource(R.string.aac_eld_success_ok)
                val showAaceldEnabling = remember { mutableStateOf(false) }
                val showAaceldSuccess = remember { mutableStateOf(false) }
                val coroutineScope = androidx.compose.runtime.rememberCoroutineScope()
                StyledToggle(
                    label = stringResource(R.string.enable_aac_eld) + " (${
                        stringResource(R.string.requires_xposed)
                    })",
                    description = stringResource(R.string.enable_aac_eld_description),
                    checked = enableAaceld.value,
                    onCheckedChange = { wantEnabled ->
                        isProcessingAaceld.value = true
                        coroutineScope.launch {
                            if (wantEnabled) {
                                showAaceldEnabling.value = true
                                val finder = me.kavishdevar.librepods.utils
                                    .RadareOffsetFinder(context)
                                val ok = finder.findA2dpOffsets()
                                if (ok) {
                                    // Pixel BT audio HAL is offload-only; our
                                    // hooks alone aren't enough to keep the
                                    // hijacked Opus slot off the DSP. Force
                                    // the global software-encoder path on too.
                                    me.kavishdevar.librepods.utils.RadareOffsetFinder
                                        .setA2dpOffloadOverride(true)
                                    me.kavishdevar.librepods.utils.RadareOffsetFinder
                                        .restartBluetoothStack()
                                    enableAaceld.value = true
                                    showAaceldEnabling.value = false
                                    showAaceldSuccess.value = true
                                } else {
                                    showAaceldEnabling.value = false
                                    enableAaceld.value = false
                                    Toast.makeText(context, aaceldNotFoundText,
                                        Toast.LENGTH_LONG).show()
                                }
                            } else {
                                me.kavishdevar.librepods.utils.RadareOffsetFinder
                                    .clearA2dpAaceldOffsets()
                                // Restore default offload behavior so AAC/SBC
                                // get hardware acceleration back when AAC-ELD
                                // is off.
                                me.kavishdevar.librepods.utils.RadareOffsetFinder
                                    .setA2dpOffloadOverride(false)
                                enableAaceld.value = false
                                Toast.makeText(context, aaceldDisabledText,
                                    Toast.LENGTH_LONG).show()
                                me.kavishdevar.librepods.utils.RadareOffsetFinder
                                    .restartBluetoothStack()
                            }
                            isProcessingAaceld.value = false
                        }
                    },
                    independent = true,
                    enabled = !isProcessingAaceld.value
                )

                if (showAaceldEnabling.value) {
                    AlertDialog(
                        onDismissRequest = { /* not dismissable while running */ },
                        title = {
                            Text(
                                aaceldEnablingTitle,
                                fontFamily = FontFamily(Font(R.font.sf_pro)),
                                fontWeight = FontWeight.Medium
                            )
                        },
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(24.dp))
                                Spacer(modifier = Modifier.width(16.dp))
                                Text(
                                    aaceldEnablingMessage,
                                    fontFamily = FontFamily(Font(R.font.sf_pro))
                                )
                            }
                        },
                        confirmButton = {}
                    )
                }

                if (showAaceldSuccess.value) {
                    AlertDialog(
                        onDismissRequest = { showAaceldSuccess.value = false },
                        title = {
                            Text(
                                aaceldSuccessTitle,
                                fontFamily = FontFamily(Font(R.font.sf_pro)),
                                fontWeight = FontWeight.Medium
                            )
                        },
                        text = {
                            Text(
                                aaceldSuccessMessage,
                                fontFamily = FontFamily(Font(R.font.sf_pro))
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = { showAaceldSuccess.value = false }) {
                                Text(
                                    aaceldSuccessOk,
                                    fontFamily = FontFamily(Font(R.font.sf_pro)),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    )
                }
            }

            if (!BuildConfig.PLAY_BUILD) {
                Spacer(modifier = Modifier.height(16.dp))
                NavigationButton(
                    to = "troubleshooting",
                    name = stringResource(R.string.troubleshooting),
                    navController = navController,
                    independent = true,
                    description = stringResource(R.string.troubleshooting_description)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(R.string.contact), style = TextStyle(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = textColor.copy(alpha = 0.6f),
                    fontFamily = FontFamily(Font(R.font.sf_pro))
                ), modifier = Modifier.padding(16.dp, bottom = 2.dp, top = 24.dp)
            )

            Spacer(modifier = Modifier.height(4.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        backgroundColor, RoundedCornerShape(28.dp)
                    )
                    .clip(RoundedCornerShape(28.dp))
            ) {
                NavigationButton(
                    to = "",
                    name = stringResource(R.string.email),
                    navController = navController,
                    onClick = {
                        val intent = Intent(Intent.ACTION_SENDTO).apply {
                            data = "mailto:".toUri()
                            putExtra(Intent.EXTRA_EMAIL, arrayOf("contact@kavish.xyz"))
                            putExtra(Intent.EXTRA_SUBJECT, "LibrePods: <SUBJECT>")
                            putExtra(
                                Intent.EXTRA_TEXT,
                                "Describe your issue here:" +
                                "\n\n\n\n----------" +
                                    "\nPhone details:" +
                                    "\nMANUFACTURER: ${Build.MANUFACTURER}" +
                                    "\nMODEL: ${Build.MODEL} (${Build.PRODUCT})" +
                                    "\nDISPLAY_VERSION: ${Build.DISPLAY} (${Build.PRODUCT})" +
                                    "\nID: ${Build.ID} (SDK ${Build.VERSION.SDK_INT_FULL})" +
                                    "\n\nApp details:" +
                                    "\nVERSION: ${BuildConfig.VERSION_NAME}" +
                                    "\nVERSION_CODE: ${BuildConfig.VERSION_CODE}" +
                                    "\nFLAVOR: ${BuildConfig.FLAVOR}" +
                                    "\nBUILD_TYPE: ${BuildConfig.BUILD_TYPE}"
                            )
                        }
                        context.startActivity(intent)
                    },
                    independent = false
                )

                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0x40888888),
                    modifier = Modifier.padding(horizontal = 12.dp)
                )

                NavigationButton(
                    to = "",
                    name = stringResource(R.string.discord),
                    navController = navController,
                    onClick = {
                        val intent =
                            Intent(Intent.ACTION_VIEW, "https://discord.gg/Ts4wupXcmc".toUri())
                        context.startActivity(intent)
                    },
                    independent = false
                )

                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0x40888888),
                    modifier = Modifier.padding(horizontal = 12.dp)
                )

                NavigationButton(
                    to = "",
                    name = stringResource(R.string.github_issues),
                    navController = navController,
                    onClick = {
                        val intent = Intent(
                            Intent.ACTION_VIEW,
                            "https://github.com/kavishdevar/librepods/issues".toUri()
                        )
                        context.startActivity(intent)
                    },
                    independent = false
                )
            }

            Spacer(modifier = Modifier.height(20.dp))
            DeviceInfoCard()

            Text(
                text = stringResource(R.string.about), style = TextStyle(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = textColor.copy(alpha = 0.6f),
                    fontFamily = FontFamily(Font(R.font.sf_pro))
                ), modifier = Modifier.padding(start = 16.dp, bottom = 2.dp, top = 24.dp)
            )

            val rowHeight = remember { mutableStateOf(0.dp) }
            val density = LocalDensity.current

            Spacer(modifier = Modifier.height(4.dp))
            Column(
                modifier = Modifier
                    .clip(RoundedCornerShape(28.dp))
                    .fillMaxWidth()
                    .background(backgroundColor, RoundedCornerShape(28.dp))
                    .padding(top = 2.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                        .onGloballyPositioned { coordinates ->
                            rowHeight.value = with(density) { coordinates.size.height.toDp() }
                        },
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.version), style = TextStyle(
                            fontSize = 16.sp,
                            color = textColor,
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                    Text(
                        text = BuildConfig.VERSION_NAME, style = TextStyle(
                            fontSize = 16.sp,
                            color = if (isDarkTheme) Color.White.copy(alpha = 0.6f) else Color.Black.copy(
                                alpha = 0.8f
                            ),
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                }
                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0x40888888),
                    modifier = Modifier.padding(horizontal = 12.dp)
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.version_code), style = TextStyle(
                            fontSize = 16.sp,
                            color = textColor,
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                    Text(
                        text = BuildConfig.VERSION_CODE.toString(), style = TextStyle(
                            fontSize = 16.sp,
                            color = if (isDarkTheme) Color.White.copy(alpha = 0.6f) else Color.Black.copy(
                                alpha = 0.8f
                            ),
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                }
                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0x40888888),
                    modifier = Modifier.padding(horizontal = 12.dp)
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.flavor), style = TextStyle(
                            fontSize = 16.sp,
                            color = textColor,
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                    Text(
                        text = BuildConfig.FLAVOR, style = TextStyle(
                            fontSize = 16.sp,
                            color = if (isDarkTheme) Color.White.copy(alpha = 0.6f) else Color.Black.copy(
                                alpha = 0.8f
                            ),
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                }
                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0x40888888),
                    modifier = Modifier.padding(horizontal = 12.dp)
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.build_type), style = TextStyle(
                            fontSize = 16.sp,
                            color = textColor,
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                    Text(
                        text = BuildConfig.BUILD_TYPE,
                        style = TextStyle(
                            fontSize = 16.sp,
                            color = if (isDarkTheme) Color.White.copy(alpha = 0.6f) else Color.Black.copy(
                                alpha = 0.8f
                            ),
                            fontFamily = FontFamily(Font(R.font.sf_pro))
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            NavigationButton(
                to = "open_source_licenses",
                name = stringResource(R.string.open_source_licenses),
                navController = navController,
                independent = true
            )

            Spacer(modifier = Modifier.height(bottomPadding))

            if (state.showCameraDialog) {
                AlertDialog(onDismissRequest = { viewModel.setShowCameraDialog(false) }, title = {
                    Text(
                        stringResource(R.string.set_custom_camera_package),
                        fontFamily = FontFamily(Font(R.font.sf_pro)),
                        fontWeight = FontWeight.Medium
                    )
                }, text = {
                    Column {
                        Text(
                            stringResource(R.string.enter_custom_camera_package),
                            fontFamily = FontFamily(Font(R.font.sf_pro)),
                            modifier = Modifier.padding(bottom = 8.dp)
                        )

                        OutlinedTextField(
                            value = state.cameraPackageValue,
                            onValueChange = {
                                viewModel.setCameraPackageValue(it)
                                viewModel.setCameraPackageError(null)
                            },
                            modifier = Modifier.fillMaxWidth(),
                            isError = state.cameraPackageError != null,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Ascii,
                                capitalization = KeyboardCapitalization.None
                            ),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = if (isDarkTheme) Color(0xFF007AFF) else Color(
                                    0xFF3C6DF5
                                ),
                                unfocusedBorderColor = if (isDarkTheme) Color.Gray else Color.LightGray
                            ),
                            supportingText = {
                                if (state.cameraPackageError != null) {
                                    Text(
                                        state.cameraPackageError ?: "",
                                        color = MaterialTheme.colorScheme.error
                                    )
                                }
                            },
                            label = { Text(stringResource(R.string.custom_camera_package)) })
                    }
                }, confirmButton = {
                    val successText = stringResource(R.string.custom_camera_package_set_success)
                    TextButton(
                        onClick = {
                            viewModel.saveCameraPackage()
                            Toast.makeText(context, successText, Toast.LENGTH_SHORT).show()
                        }) {
                        Text(
                            "Save",
                            fontFamily = FontFamily(Font(R.font.sf_pro)),
                            fontWeight = FontWeight.Medium
                        )
                    }
                }, dismissButton = {
                    TextButton(
                        onClick = { viewModel.setShowCameraDialog(false) }) {
                        Text(
                            "Cancel",
                            fontFamily = FontFamily(Font(R.font.sf_pro)),
                            fontWeight = FontWeight.Medium
                        )
                    }
                })
            }
        }
    }
}
