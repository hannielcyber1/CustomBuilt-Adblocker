package com.shieldnet.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val BgDark = Color(0xFF0D1117)
val CardDark = Color(0xFF161B22)
val CardHoverDark = Color(0xFF21262D)
val AccentGreen = Color(0xFF238636)
val AccentRed = Color(0xFFDA3633)
val AccentBlue = Color(0xFF58A6FF)
val AccentPurple = Color(0xFF8957E5)
val TextMain = Color(0xFFF0F6FC)
val TextMuted = Color(0xFF8B949E)
val BorderSubtle = Color(0xFF30363D)

private val DarkColorScheme = darkColorScheme(
    primary = AccentBlue,
    secondary = AccentGreen,
    background = BgDark,
    surface = CardDark,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = TextMain,
    onSurface = TextMain,
)

@Composable
fun ShieldNetTheme(
    darkTheme: Boolean = true, // Default to Cybersecurity Dark
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
