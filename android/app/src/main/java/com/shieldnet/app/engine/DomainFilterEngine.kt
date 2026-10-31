package com.shieldnet.app.engine

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

data class FilterDecision(
    val allowed: Boolean,
    val domain: String,
    val rule: DomainRule? = null,
    val reason: String = "default_allow",
    val category: RuleCategory? = null
)

class DomainFilterEngine {
    private val allowTrie = DomainTrie()
    private val blockTrie = DomainTrie()
    private val lock = Any()

    val totalQueries = AtomicLong(0)
    val blockedQueries = AtomicLong(0)
    val allowedQueries = AtomicLong(0)
    val categoryCounts = ConcurrentHashMap<String, Long>()

    private val enabledCategories = ConcurrentHashMap.newKeySet<RuleCategory>().apply {
        addAll(RuleCategory.values())
    }

    fun setCategoryEnabled(category: RuleCategory, enabled: Boolean) {
        if (enabled) {
            enabledCategories.add(category)
        } else {
            enabledCategories.remove(category)
        }
    }

    fun isCategoryEnabled(category: RuleCategory): Boolean {
        return enabledCategories.contains(category)
    }

    fun addRule(rule: DomainRule) {
        synchronized(lock) {
            if (rule.ruleType == RuleType.ALLOW) {
                allowTrie.insert(rule)
            } else {
                blockTrie.insert(rule)
            }
        }
    }

    fun loadRules(rules: List<DomainRule>, clearExisting: Boolean = true) {
        val newAllow = DomainTrie()
        val newBlock = DomainTrie()

        for (rule in rules) {
            if (rule.ruleType == RuleType.ALLOW) {
                newAllow.insert(rule)
            } else {
                newBlock.insert(rule)
            }
        }

        synchronized(lock) {
            if (clearExisting) {
                allowTrie.clear()
                blockTrie.clear()
                for (rule in rules) {
                    if (rule.ruleType == RuleType.ALLOW) allowTrie.insert(rule)
                    else blockTrie.insert(rule)
                }
            } else {
                for (rule in rules) {
                    addRule(rule)
                }
            }
        }
    }

    fun evaluate(domain: String): FilterDecision {
        val normalized = DomainRule.normalizeDomain(domain)
            ?: return FilterDecision(allowed = true, domain = domain, reason = "invalid_domain_allowed")

        val reversedLabels = normalized.split(".").reversed()
        totalQueries.incrementAndGet()

        synchronized(lock) {
            // 1. Allowlist precedence
            val allowRule = allowTrie.match(reversedLabels)
            if (allowRule != null) {
                allowedQueries.incrementAndGet()
                return FilterDecision(
                    allowed = true,
                    domain = normalized,
                    rule = allowRule,
                    reason = "allowlist_precedence",
                    category = allowRule.category
                )
            }

            // 2. Blocklist matching
            val blockRule = blockTrie.match(reversedLabels)
            if (blockRule != null) {
                // Check category toggle
                if (!enabledCategories.contains(blockRule.category)) {
                    allowedQueries.incrementAndGet()
                    return FilterDecision(
                        allowed = true,
                        domain = normalized,
                        rule = blockRule,
                        reason = "category_disabled_allow",
                        category = blockRule.category
                    )
                }

                blockedQueries.incrementAndGet()
                val catName = blockRule.category.displayName
                categoryCounts.compute(catName) { _, v -> (v ?: 0L) + 1L }

                return FilterDecision(
                    allowed = false,
                    domain = normalized,
                    rule = blockRule,
                    reason = "blocklist_match",
                    category = blockRule.category
                )
            }

            // 3. Default: Allowed
            allowedQueries.incrementAndGet()
            return FilterDecision(
                allowed = true,
                domain = normalized,
                reason = "default_allow"
            )
        }
    }

    fun getRulesCount(): Pair<Int, Int> {
        synchronized(lock) {
            return Pair(allowTrie.size, blockTrie.size)
        }
    }

    fun resetStats() {
        totalQueries.set(0)
        blockedQueries.set(0)
        allowedQueries.set(0)
        categoryCounts.clear()
    }
}
