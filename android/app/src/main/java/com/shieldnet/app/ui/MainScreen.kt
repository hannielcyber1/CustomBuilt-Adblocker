package com.shieldnet.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.shieldnet.app.engine.DomainRule
import com.shieldnet.app.engine.RuleCategory
import com.shieldnet.app.engine.RuleType
import com.shieldnet.app.vpn.ShieldNetVpnService

@Composable
fun MainScreen(
    isProtectionActive: Boolean,
    onToggleProtection: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = CardDark,
                contentColor = TextMain
            ) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Lock, contentDescription = "Dashboard") },
                    label = { Text("Dashboard", fontSize = 11.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.List, contentDescription = "Activity") },
                    label = { Text("Activity", fontSize = 11.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.CheckCircle, contentDescription = "Blocklists") },
                    label = { Text("Blocklists", fontSize = 11.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    icon = { Icon(Icons.Default.Edit, contentDescription = "Rules") },
                    label = { Text("Rules", fontSize = 11.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 4,
                    onClick = { selectedTab = 4 },
                    icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                    label = { Text("Settings", fontSize = 11.sp) }
                )
            }
        },
        containerColor = BgDark
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            when (selectedTab) {
                0 -> DashboardScreen(isProtectionActive, onToggleProtection)
                1 -> ActivityScreen()
                2 -> BlocklistsScreen()
                3 -> CustomRulesScreen()
                4 -> SettingsScreen()
            }
        }
    }
}

// ==========================================
// SCREEN 1: DASHBOARD
// ==========================================
@Composable
fun DashboardScreen(
    isProtectionActive: Boolean,
    onToggleProtection: () -> Unit
) {
    val totalBlocked = remember { derivedStateOf { ShieldNetVpnService.engine.blockedQueries.get() } }
    val totalAllowed = remember { derivedStateOf { ShieldNetVpnService.engine.allowedQueries.get() } }
    val rulesCount = remember { derivedStateOf { ShieldNetVpnService.engine.getRulesCount() } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // App Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text("🛡️ ShieldNet", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = TextMain)
            Text("v1.0.0", fontSize = 12.sp, color = AccentBlue)
        }

        Spacer(modifier = Modifier.height(30.dp))

        // Big Shield Animated Toggle
        Box(
            modifier = Modifier
                .size(140.dp)
                .clip(CircleShape)
                .background(if (isProtectionActive) AccentGreen.copy(alpha = 0.15f) else Color.DarkGray.copy(alpha = 0.2f))
                .border(
                    width = 3.dp,
                    color = if (isProtectionActive) AccentGreen else Color.Gray,
                    shape = CircleShape
                ),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Lock,
                contentDescription = null,
                modifier = Modifier.size(72.dp),
                tint = if (isProtectionActive) AccentGreen else Color.Gray
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = if (isProtectionActive) "PROTECTION ACTIVE" else "PROTECTION PAUSED",
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            color = if (isProtectionActive) AccentGreen else TextMuted
        )

        Text(
            text = if (isProtectionActive)
                "Filtering tracking, ads, and telemetry on-device."
            else
                "Tap to start local DNS-based privacy protection.",
            fontSize = 12.sp,
            color = TextMuted,
            modifier = Modifier.padding(top = 4.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onToggleProtection,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isProtectionActive) AccentRed else AccentGreen
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth(0.8f)
                .height(48.dp)
        ) {
            Text(
                text = if (isProtectionActive) "PAUSE PROTECTION" else "START PROTECTION",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        // Metric Cards Grid
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "QUERIES BLOCKED",
                value = "${totalBlocked.value}",
                color = AccentRed
            )
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "QUERIES PERMITTED",
                value = "${totalAllowed.value}",
                color = AccentGreen
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "ACTIVE RULES",
                value = "${rulesCount.value.first + rulesCount.value.second}",
                color = AccentPurple
            )
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "UPSTREAM RESOLVER",
                value = ShieldNetVpnService.upstreamDnsIp,
                color = AccentBlue
            )
        }
    }
}

@Composable
fun MetricCard(modifier: Modifier = Modifier, title: String, value: String, color: Color) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = CardDark),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(title, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextMuted)
            Spacer(modifier = Modifier.height(4.dp))
            Text(value, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = color)
        }
    }
}

// ==========================================
// SCREEN 2: ACTIVITY LOG
// ==========================================
@Composable
fun ActivityScreen() {
    var searchQuery by remember { mutableStateOf("") }
    val mockActivity = remember {
        listOf(
            Triple("ad.doubleclick.net", "BLOCKED", "Advertising"),
            Triple("telemetry.sdk.com", "BLOCKED", "Telemetry"),
            Triple("github.com", "ALLOWED", "General"),
            Triple("analytics.google.com", "BLOCKED", "Analytics"),
            Triple("wikipedia.org", "ALLOWED", "General")
        )
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Query Activity", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextMain)
        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search queried domains...", color = TextMuted) },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = TextMain,
                unfocusedTextColor = TextMain,
                focusedBorderColor = AccentBlue,
                unfocusedBorderColor = BorderSubtle
            )
        )

        Spacer(modifier = Modifier.height(16.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(mockActivity.filter { it.first.contains(searchQuery, ignoreCase = true) }) { item ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp).fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(item.first, fontWeight = FontWeight.SemiBold, color = TextMain)
                            Text(item.third, fontSize = 11.sp, color = TextMuted)
                        }
                        Text(
                            text = item.second,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            color = if (item.second == "BLOCKED") AccentRed else AccentGreen
                        )
                    }
                }
            }
        }
    }
}

// ==========================================
// SCREEN 3: BLOCKLISTS
// ==========================================
@Composable
fun BlocklistsScreen() {
    val blocklists = remember {
        listOf(
            Pair("StevenBlack Unified Hosts", "Unified ad, malware, and tracker blocklist"),
            Pair("AdGuard DNS Filter", "Specialized DNS filter for ad services and telemetry"),
            Pair("OISD Basic", "High compatibility domain list with low false positives")
        )
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Blocklist Subscriptions", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextMain)
        Spacer(modifier = Modifier.height(12.dp))

        blocklists.forEach { (name, desc) ->
            var enabled by remember { mutableStateOf(true) }
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                colors = CardDefaults.cardColors(containerColor = CardDark),
                shape = RoundedCornerShape(10.dp)
            ) {
                Row(
                    modifier = Modifier.padding(16.dp).fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(name, fontWeight = FontWeight.Bold, color = TextMain)
                        Text(desc, fontSize = 11.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                    }
                    Switch(
                        checked = enabled,
                        onCheckedChange = { enabled = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = AccentGreen, checkedTrackColor = AccentGreen.copy(alpha = 0.5f))
                    )
                }
            }
        }
    }
}

// ==========================================
// SCREEN 4: CUSTOM RULES
// ==========================================
@Composable
fun CustomRulesScreen() {
    var newDomain by remember { mutableStateOf("") }
    var isBlock by remember { mutableStateOf(true) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Custom Rules", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextMain)
        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value = newDomain,
            onValueChange = { newDomain = it },
            placeholder = { Text("e.g. tracker.example.com", color = TextMuted) },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = TextMain,
                unfocusedTextColor = TextMain,
                focusedBorderColor = AccentBlue,
                unfocusedBorderColor = BorderSubtle
            )
        )

        Spacer(modifier = Modifier.height(8.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = isBlock, onClick = { isBlock = true })
            Text("Block", color = TextMain, modifier = Modifier.padding(end = 16.dp))
            RadioButton(selected = !isBlock, onClick = { isBlock = false })
            Text("Allow", color = TextMain)
            Spacer(modifier = Modifier.weight(1f))
            Button(
                onClick = {
                    if (newDomain.isNotBlank()) {
                        val ruleType = if (isBlock) RuleType.BLOCK else RuleType.ALLOW
                        val rule = DomainRule.create(newDomain, ruleType, RuleCategory.CUSTOM)
                        if (rule != null) {
                            ShieldNetVpnService.engine.addRule(rule)
                            newDomain = ""
                        }
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = AccentGreen)
            ) {
                Text("+ Add Rule")
            }
        }
    }
}

// ==========================================
// SCREEN 5: SETTINGS
// ==========================================
@Composable
fun SettingsScreen() {
    var upstreamDns by remember { mutableStateOf(ShieldNetVpnService.upstreamDnsIp) }
    var blockAdultContent by remember { 
        mutableStateOf(ShieldNetVpnService.engine.isCategoryEnabled(RuleCategory.ADULT_CONTENT)) 
    }
    var blockGambling by remember { 
        mutableStateOf(ShieldNetVpnService.engine.isCategoryEnabled(RuleCategory.GAMBLING)) 
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Settings & Diagnostics", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextMain)
        Spacer(modifier = Modifier.height(16.dp))

        // Automatic Content Protection Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Content Protection & Filtering", fontWeight = FontWeight.Bold, color = TextMain)
                Text("Automatically block explicit/adult sites and gambling.", fontSize = 11.sp, color = TextMuted)
                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("🔞 Block Adult / Explicit Sites", fontWeight = FontWeight.SemiBold, color = TextMain)
                        Text("Blocks pornographic, NSFW, and adult sites automatically.", fontSize = 11.sp, color = TextMuted)
                    }
                    Switch(
                        checked = blockAdultContent,
                        onCheckedChange = {
                            blockAdultContent = it
                            ShieldNetVpnService.engine.setCategoryEnabled(RuleCategory.ADULT_CONTENT, it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = AccentGreen,
                            checkedTrackColor = AccentGreen.copy(alpha = 0.5f)
                        )
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("🎰 Block Online Gambling", fontWeight = FontWeight.SemiBold, color = TextMain)
                        Text("Blocks betting and casino domains automatically.", fontSize = 11.sp, color = TextMuted)
                    }
                    Switch(
                        checked = blockGambling,
                        onCheckedChange = {
                            blockGambling = it
                            ShieldNetVpnService.engine.setCategoryEnabled(RuleCategory.GAMBLING, it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = AccentGreen,
                            checkedTrackColor = AccentGreen.copy(alpha = 0.5f)
                        )
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Upstream DNS Resolver", fontWeight = FontWeight.Bold, color = TextMain)
                Text("DNS requests for permitted domains are forwarded to this resolver.", fontSize = 11.sp, color = TextMuted)
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = upstreamDns,
                    onValueChange = {
                        upstreamDns = it
                        ShieldNetVpnService.upstreamDnsIp = it
                    },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("⚠️ Private DNS Conflict Notice", fontWeight = FontWeight.Bold, color = Color(0xFFD29922))
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Android's system 'Private DNS' (DNS-over-TLS) takes precedence over local VPN DNS services. " +
                            "For ShieldNet to block trackers across all apps, ensure Private DNS is set to 'Off' or 'Automatic' in Android Network Settings.",
                    fontSize = 11.sp,
                    color = TextMuted
                )
            }
        }
    }
}
