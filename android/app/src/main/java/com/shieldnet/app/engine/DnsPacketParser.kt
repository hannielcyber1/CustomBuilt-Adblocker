package com.shieldnet.app.engine

import java.nio.ByteBuffer

data class ParsedDnsQuery(
    val domain: String,
    val qType: Int, // 1 for A, 28 for AAAA
    val transactionId: Short,
    val dnsOffset: Int,
    val dnsLength: Int,
    val udpOffset: Int,
    val isTcp: Boolean
)

object DnsPacketParser {
    const val QTYPE_A = 1
    const val QTYPE_AAAA = 28

    /**
     * Inspects an IPv4 packet buffer and extracts DNS query details if it targets port 53.
     */
    fun parseQueryFromIpPacket(buffer: ByteBuffer, packetLength: Int): ParsedDnsQuery? {
        if (packetLength < 28) return null // 20 IP + 8 UDP

        val version = (buffer.get(0).toInt() ushr 4) and 0x0F
        if (version != 4) return null // Handle IPv4

        val ipHeaderLen = (buffer.get(0).toInt() and 0x0F) * 4
        val protocol = buffer.get(9).toInt() and 0xFF

        if (protocol != 17) {
            // Not UDP (could be TCP DNS on port 53)
            return null
        }

        val udpOffset = ipHeaderLen
        if (packetLength < udpOffset + 8) return null

        val dstPort = buffer.getShort(udpOffset + 2).toInt() and 0xFFFF
        if (dstPort != 53) return null

        val dnsOffset = udpOffset + 8
        val dnsLen = packetLength - dnsOffset
        if (dnsLen < 12) return null // Minimum DNS header

        val txId = buffer.getShort(dnsOffset)
        val flags = buffer.getShort(dnsOffset + 2).toInt() and 0xFFFF
        val qr = (flags ushr 15) and 0x01
        if (qr != 0) return null // Not a query (it is already a response)

        val qdCount = buffer.getShort(dnsOffset + 4).toInt() and 0xFFFF
        if (qdCount < 1) return null

        // Parse QNAME
        var pos = dnsOffset + 12
        val domainBuilder = StringBuilder()

        while (pos < packetLength) {
            val len = buffer.get(pos).toInt() and 0xFF
            pos++
            if (len == 0) break // Root null label
            if ((len and 0xC0) == 0xC0) {
                // Compression pointer
                pos++
                break
            }
            if (pos + len > packetLength) return null

            if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
            val labelBytes = ByteArray(len)
            val currentPos = buffer.position()
            buffer.position(pos)
            buffer.get(labelBytes)
            buffer.position(currentPos)
            domainBuilder.append(String(labelBytes, Charsets.US_ASCII))
            pos += len
        }

        if (pos + 4 > packetLength) return null
        val qType = buffer.getShort(pos).toInt() and 0xFFFF

        return ParsedDnsQuery(
            domain = domainBuilder.toString().lowercase(),
            qType = qType,
            transactionId = txId,
            dnsOffset = dnsOffset,
            dnsLength = dnsLen,
            udpOffset = udpOffset,
            isTcp = false
        )
    }

    /**
     * Synthesizes a DNS response returning 0.0.0.0 (for A) or :: (for AAAA) or NXDOMAIN.
     */
    fun buildBlockResponse(
        originalPacket: ByteArray,
        packetLen: Int,
        query: ParsedDnsQuery,
        nxdomain: Boolean = false,
        ttlSeconds: Int = 300
    ): ByteArray {
        val respBuffer = ByteBuffer.allocate(packetLen + 64)
        val srcIp = ByteArray(4)
        val dstIp = ByteArray(4)

        // Read original IPs
        System.arraycopy(originalPacket, 12, srcIp, 0, 4)
        System.arraycopy(originalPacket, 16, dstIp, 0, 4)

        val srcPort = ((originalPacket[query.udpOffset].toInt() and 0xFF) shl 8) or
                (originalPacket[query.udpOffset + 1].toInt() and 0xFF)
        val dstPort = ((originalPacket[query.udpOffset + 2].toInt() and 0xFF) shl 8) or
                (originalPacket[query.udpOffset + 3].toInt() and 0xFF)

        // 1. Copy original IP Header and swap IPs
        respBuffer.put(originalPacket, 0, query.udpOffset)
        respBuffer.put(12, dstIp[0])
        respBuffer.put(13, dstIp[1])
        respBuffer.put(14, dstIp[2])
        respBuffer.put(15, dstIp[3])
        respBuffer.put(16, srcIp[0])
        respBuffer.put(17, srcIp[1])
        respBuffer.put(18, srcIp[2])
        respBuffer.put(19, srcIp[3])

        // 2. DNS payload position
        val dnsStart = query.udpOffset + 8
        respBuffer.position(dnsStart)

        // DNS Header
        respBuffer.putShort(query.transactionId)
        val flags = if (nxdomain) 0x8183.toShort() else 0x8180.toShort() // Standard response, Recursion Available, NoError or NXDomain
        respBuffer.putShort(flags)
        respBuffer.putShort(1.toShort()) // QDCOUNT
        val anCount = if (nxdomain) 0.toShort() else 1.toShort()
        respBuffer.putShort(anCount) // ANCOUNT
        respBuffer.putShort(0.toShort()) // NSCOUNT
        respBuffer.putShort(0.toShort()) // ARCOUNT

        // Question section (copy from original packet)
        val questionLen = query.dnsLength - 12
        respBuffer.put(originalPacket, query.dnsOffset + 12, questionLen)

        // Answer Section if not NXDOMAIN
        if (!nxdomain) {
            // Compressed pointer to question name at offset 12
            respBuffer.put(0xC0.toByte())
            respBuffer.put(0x0C.toByte())

            if (query.qType == QTYPE_AAAA) {
                respBuffer.putShort(QTYPE_AAAA.toShort())
                respBuffer.putShort(1.toShort()) // IN class
                respBuffer.putInt(ttlSeconds)
                respBuffer.putShort(16.toShort()) // RDLENGTH 16 bytes for ::
                respBuffer.put(ByteArray(16)) // 00...00
            } else {
                // A record: 0.0.0.0
                respBuffer.putShort(QTYPE_A.toShort())
                respBuffer.putShort(1.toShort()) // IN class
                respBuffer.putInt(ttlSeconds)
                respBuffer.putShort(4.toShort()) // RDLENGTH 4 bytes
                respBuffer.put(byteArrayOf(0, 0, 0, 0))
            }
        }

        val totalLen = respBuffer.position()
        val totalDnsLen = totalLen - dnsStart
        val udpTotalLen = totalDnsLen + 8

        // Fix IP Total Length
        respBuffer.putShort(2, totalLen.toShort())

        // Recalculate IPv4 Header Checksum
        respBuffer.putShort(10, 0.toShort())
        var ipChecksum = 0
        for (i in 0 until query.udpOffset step 2) {
            val word = (respBuffer.get(i).toInt() and 0xFF shl 8) or (respBuffer.get(i + 1).toInt() and 0xFF)
            ipChecksum += word
        }
        while ((ipChecksum ushr 16) != 0) {
            ipChecksum = (ipChecksum and 0xFFFF) + (ipChecksum ushr 16)
        }
        val finalIpChecksum = (ipChecksum.inv() and 0xFFFF).toShort()
        respBuffer.putShort(10, finalIpChecksum)

        // Fix UDP Header (swap ports, set length, 0 checksum)
        respBuffer.putShort(query.udpOffset, dstPort.toShort())
        respBuffer.putShort(query.udpOffset + 2, srcPort.toShort())
        respBuffer.putShort(query.udpOffset + 4, udpTotalLen.toShort())
        respBuffer.putShort(query.udpOffset + 6, 0.toShort()) // Optional in IPv4 UDP

        val result = ByteArray(totalLen)
        respBuffer.position(0)
        respBuffer.get(result)
        return result
    }
}
