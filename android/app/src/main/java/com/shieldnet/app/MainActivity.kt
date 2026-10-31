package com.shieldnet.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf
import com.shieldnet.app.ui.MainScreen
import com.shieldnet.app.ui.ShieldNetTheme
import com.shieldnet.app.vpn.ShieldNetVpnService

class MainActivity : ComponentActivity() {

    private val isProtectionActiveState = mutableStateOf(false)

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            ShieldNetTheme {
                MainScreen(
                    isProtectionActive = isProtectionActiveState.value,
                    onToggleProtection = { toggleProtection() }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        isProtectionActiveState.value = ShieldNetVpnService.isRunning.get()
    }

    private fun toggleProtection() {
        if (ShieldNetVpnService.isRunning.get()) {
            stopVpnService()
        } else {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                vpnConsentLauncher.launch(vpnIntent)
            } else {
                startVpnService()
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, ShieldNetVpnService::class.java).apply {
            action = ShieldNetVpnService.ACTION_START
        }
        startForegroundService(intent)
        isProtectionActiveState.value = true
    }

    private fun stopVpnService() {
        val intent = Intent(this, ShieldNetVpnService::class.java).apply {
            action = ShieldNetVpnService.ACTION_STOP
        }
        startService(intent)
        isProtectionActiveState.value = false
    }
}
