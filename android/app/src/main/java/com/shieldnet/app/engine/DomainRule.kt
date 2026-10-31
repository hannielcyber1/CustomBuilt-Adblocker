package com.shieldnet.app.engine

import java.net.IDN
import java.util.Locale

enum class RuleType {
    BLOCK,
    ALLOW
}

enum class RuleCategory(val displayName: String) {
    ADVERTISING("Advertising"),
    TRACKING("Tracking"),
    ANALYTICS("Analytics"),
    TELEMETRY("Telemetry"),
    MALWARE("Malware"),
    ADULT_CONTENT("Adult Content"),
    GAMBLING("Gambling"),
    CUSTOM("Custom"),
    GENERAL("General")
}

data class DomainRule(
    val pattern: String,
    val ruleType: RuleType = RuleType.BLOCK,
    val category: RuleCategory = RuleCategory.GENERAL,
    val isWildcard: Boolean = true,
    val sourceList: String = "custom",
    val comment: String? = null
) {
    companion object {
        private val LABEL_REGEX = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

        fun normalizeDomain(rawDomain: String?): String? {
            if (rawDomain.isNullOrBlank()) return null

            var cleaned = rawDomain.trim().lowercase(Locale.ROOT)

            // Strip scheme if present
            if (cleaned.contains("://")) {
                cleaned = cleaned.substringAfter("://")
            }

            // Strip path and query
            if (cleaned.contains("/")) {
                cleaned = cleaned.substringBefore("/")
            }
            if (cleaned.contains("?")) {
                cleaned = cleaned.substringBefore("?")
            }

            // Strip port
            if (cleaned.contains(":") && !cleaned.startsWith("[")) {
                cleaned = cleaned.substringBefore(":")
            }

            // Strip trailing dot
            cleaned = cleaned.trimEnd('.')

            if (cleaned.isEmpty() || cleaned.length > 253) return null

            // IDN / Punycode conversion
            return try {
                val ascii = IDN.toASCII(cleaned)
                val labels = ascii.split(".")
                if (labels.isEmpty()) return null
                for (label in labels) {
                    if (label.isEmpty() || label.length > 63) return null
                    if (!LABEL_REGEX.matches(label)) return null
                }
                ascii
            } catch (e: Exception) {
                null
            }
        }

        fun create(
            domain: String,
            ruleType: RuleType = RuleType.BLOCK,
            category: RuleCategory = RuleCategory.GENERAL,
            isWildcard: Boolean = true,
            sourceList: String = "custom",
            comment: String? = null
        ): DomainRule? {
            val normalized = normalizeDomain(domain) ?: return null
            return DomainRule(
                pattern = normalized,
                ruleType = ruleType,
                category = category,
                isWildcard = isWildcard,
                sourceList = sourceList,
                comment = comment
            )
        }
    }
}
