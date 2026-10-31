package com.shieldnet.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.shieldnet.app.MainActivity
import com.shieldnet.app.R
import com.shieldnet.app.engine.DnsPacketParser
import com.shieldnet.app.engine.DomainFilterEngine
import com.shieldnet.app.engine.DomainRule
import com.shieldnet.app.engine.RuleCategory
import com.shieldnet.app.engine.RuleType
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class ShieldNetVpnService : VpnService() {

    companion object {
        const val TAG = "ShieldNetVpn"
        const val NOTIFICATION_CHANNEL_ID = "shieldnet_vpn_channel"
        const val NOTIFICATION_ID = 1001

        const val ACTION_START = "com.shieldnet.app.START"
        const val ACTION_STOP = "com.shieldnet.app.STOP"

        val isRunning = AtomicBoolean(false)
        val engine = DomainFilterEngine()
        var upstreamDnsIp: String = "9.9.9.9"
        var upstreamDnsPort: Int = 53
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var vpnJob: Job? = null
    private var connectivityManager: ConnectivityManager? = null

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Network available: $network")
        }

        override fun onLost(network: Network) {
            Log.w(TAG, "Network lost: $network")
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        connectivityManager?.registerDefaultNetworkCallback(networkCallback)

        // Seed default protection rules if engine is empty
        if (engine.getRulesCount().second == 0) {
            // Ad networks & tracking
            engine.addRule(DomainRule.create("doubleclick.net", RuleType.BLOCK, RuleCategory.ADVERTISING)!!)
            engine.addRule(DomainRule.create("telemetry.sdk.com", RuleType.BLOCK, RuleCategory.TELEMETRY)!!)
            engine.addRule(DomainRule.create("analytics.google.com", RuleType.BLOCK, RuleCategory.ANALYTICS)!!)

            // Automatic Adult Content / Explicit domain baseline
            val adultDomains = listOf(
                "pornhub.com", "xvideos.com", "xhamster.com", "redtube.com", "youporn.com",
                "xnxx.com", "beeg.com", "tube8.com", "spankbang.com", "brazzers.com",
                "onlyfans.com", "chaturbate.com", "livejasmin.com", "stripchat.com", "bongacams.com"
            )
            for (domain in adultDomains) {
                DomainRule.create(domain, RuleType.BLOCK, RuleCategory.ADULT_CONTENT)?.let {
                    engine.addRule(it)
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        if (action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning.get()) return

        val notification = buildNotification("ShieldNet is actively protecting your device")
        startForeground(NOTIFICATION_ID, notification)

        try {
            val builder = Builder()
                .setSession("ShieldNet DNS Filter")
                // Virtual IP allocated to TUN interface
                .addAddress("10.255.0.1", 32)
                // Set DNS server to virtual interface IP
                .addDnsServer("10.255.0.1")
                // Route ONLY the DNS server IP through the VPN TUN.
                // All normal TCP/UDP application traffic remains native, avoiding bandwidth/battery drain!
                .addRoute("10.255.0.1", 32)
                .setBlocking(true)
                .setMtu(1500)

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            isRunning.set(true)
            Log.i(TAG, "VPN TUN interface established successfully")

            vpnJob = serviceScope.launch {
                runPacketLoop(vpnInterface!!)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN: ${e.message}", e)
            stopVpn()
        }
    }

    private suspend fun runPacketLoop(tunFd: ParcelFileDescriptor) = withContext(Dispatchers.IO) {
        val inputStream = FileInputStream(tunFd.fileDescriptor)
        val outputStream = FileOutputStream(tunFd.fileDescriptor)
        val packetBuffer = ByteArray(4096)
        val byteBuf = ByteBuffer.wrap(packetBuffer)

        Log.i(TAG, "Started TUN packet read loop")

        while (isActive && isRunning.get()) {
            try {
                val length = inputStream.read(packetBuffer)
                if (length <= 0) continue

                byteBuf.clear()
                byteBuf.limit(length)

                val query = DnsPacketParser.parseQueryFromIpPacket(byteBuf, length)
                if (query != null) {
                    // Evaluate queried domain
                    val decision = engine.evaluate(query.domain)

                    if (!decision.allowed) {
                        // Synthesize block response (0.0.0.0)
                        val blockResponse = DnsPacketParser.buildBlockResponse(
                            originalPacket = packetBuffer,
                            packetLen = length,
                            query = query,
                            nxdomain = false
                        )
                        synchronized(outputStream) {
                            outputStream.write(blockResponse)
                        }
                    } else {
                        // Forward permitted DNS request to upstream resolver
                        launch(Dispatchers.IO) {
                            forwardDnsUpstream(packetBuffer, length, query, outputStream)
                        }
                    }
                }
            } catch (e: Exception) {
                if (isActive) {
                    Log.d(TAG, "Packet loop exception: ${e.message}")
                }
            }
        }
    }

    private fun forwardDnsUpstream(
        packet: ByteArray,
        packetLen: Int,
        query: com.shieldnet.app.engine.ParsedDnsQuery,
        outputStream: FileOutputStream
    ) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            // CRUCIAL: Protect socket to prevent packet loop into VPN interface!
            protect(socket)
            socket.soTimeout = 2500

            val dnsPayload = ByteArray(query.dnsLength)
            System.arraycopy(packet, query.dnsOffset, dnsPayload, 0, query.dnsLength)

            val upstreamAddr = InetAddress.getByName(upstreamDnsIp)
            val sendPacket = DatagramPacket(dnsPayload, query.dnsLength, upstreamAddr, upstreamDnsPort)
            socket.send(sendPacket)

            val recvBuf = ByteArray(4096)
            val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
            socket.receive(recvPacket)

            // Craft raw IP/UDP response from upstream DNS reply
            val forwardResp = DnsPacketParser.buildBlockResponse(
                originalPacket = packet,
                packetLen = packetLen,
                query = query,
                nxdomain = false
            )
            // Replace DNS payload with upstream response
            val finalResp = ByteBuffer.allocate(query.udpOffset + 8 + recvPacket.length)
            finalResp.put(forwardResp, 0, query.udpOffset + 8)
            finalResp.put(recvBuf, 0, recvPacket.length)

            // Fix lengths
            val totalLen = finalResp.position()
            finalResp.putShort(2, totalLen.toShort())
            finalResp.putShort(query.udpOffset + 4, (recvPacket.length + 8).toShort())

            synchronized(outputStream) {
                outputStream.write(finalResp.array(), 0, totalLen)
            }
        } catch (e: Exception) {
            Log.d(TAG, "Upstream DNS forwarding failed for ${query.domain}: ${e.message}")
        } finally {
            socket?.close()
        }
    }

    private fun stopVpn() {
        isRunning.set(false)
        vpnJob?.cancel()
        serviceScope.cancel()

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "ShieldNet VPN Service stopped.")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                getString(R.string.vpn_notification_channel),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows active ShieldNet DNS protection status"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ShieldNetVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Pause", stopIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        connectivityManager?.unregisterNetworkCallback(networkCallback)
        stopVpn()
    }
}
