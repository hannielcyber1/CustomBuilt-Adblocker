package com.shieldnet.app

import com.shieldnet.app.engine.DnsPacketParser
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class DnsPacketParserTest {

    @Test
    fun testParseUdpDnsQuery() {
        // Construct a synthetic IPv4 UDP DNS query packet for 'ads.test.com'
        val buffer = ByteBuffer.allocate(128)

        // 1. IPv4 Header (20 bytes)
        buffer.put(0x45.toByte()) // Version 4, IHL 5
        buffer.put(0x00.toByte()) // DSCP/ECN
        buffer.putShort(0.toShort()) // Total length placeholder
        buffer.putShort(0x1234.toShort()) // ID
        buffer.putShort(0x4000.toShort()) // Flags (DF)
        buffer.put(64.toByte()) // TTL
        buffer.put(17.toByte()) // Protocol 17 = UDP
        buffer.putShort(0.toShort()) // Checksum
        buffer.put(byteArrayOf(192.toByte(), 168.toByte(), 1, 10)) // Src IP: 192.168.1.10
        buffer.put(byteArrayOf(10, 255.toByte(), 0, 1)) // Dst IP: 10.255.0.1 (VPN DNS)

        // 2. UDP Header (8 bytes)
        buffer.putShort(54321.toShort()) // Src Port
        buffer.putShort(53.toShort()) // Dst Port 53
        buffer.putShort(0.toShort()) // Length placeholder
        buffer.putShort(0.toShort()) // Checksum

        // 3. DNS Header (12 bytes)
        val dnsStart = buffer.position()
        buffer.putShort(0xABCD.toShort()) // Tx ID
        buffer.putShort(0x0100.toShort()) // Standard query
        buffer.putShort(1.toShort()) // QDCOUNT
        buffer.putShort(0.toShort()) // ANCOUNT
        buffer.putShort(0.toShort()) // NSCOUNT
        buffer.putShort(0.toShort()) // ARCOUNT

        // QNAME: 3ads4test3com0
        buffer.put(3.toByte())
        buffer.put("ads".toByteArray(Charsets.US_ASCII))
        buffer.put(4.toByte())
        buffer.put("test".toByteArray(Charsets.US_ASCII))
        buffer.put(3.toByte())
        buffer.put("com".toByteArray(Charsets.US_ASCII))
        buffer.put(0.toByte())

        // QTYPE = 1 (A), QCLASS = 1 (IN)
        buffer.putShort(1.toShort())
        buffer.putShort(1.toShort())

        val totalLen = buffer.position()
        buffer.putShort(2, totalLen.toShort())
        buffer.putShort(24, (totalLen - 20).toShort())

        buffer.flip()
        val query = DnsPacketParser.parseQueryFromIpPacket(buffer, totalLen)

        assertNotNull(query)
        assertEquals("ads.test.com", query!!.domain)
        assertEquals(1, query.qType)
        assertEquals(0xABCD.toShort(), query.transactionId)
    }
}
