package com.shieldnet.app

import com.shieldnet.app.engine.DomainFilterEngine
import com.shieldnet.app.engine.DomainRule
import com.shieldnet.app.engine.RuleCategory
import com.shieldnet.app.engine.RuleType
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class DomainFilterEngineTest {

    private lateinit var engine: DomainFilterEngine

    @Before
    fun setUp() {
        engine = DomainFilterEngine()
    }

    @Test
    fun testExactAndWildcardBlocking() {
        val rule = DomainRule.create("doubleclick.net", RuleType.BLOCK, RuleCategory.ADVERTISING, isWildcard = true)
        assertNotNull(rule)
        engine.addRule(rule!!)

        val exactDec = engine.evaluate("doubleclick.net")
        assertFalse(exactDec.allowed)
        assertEquals("blocklist_match", exactDec.reason)

        val subDec = engine.evaluate("ad.doubleclick.net")
        assertFalse(subDec.allowed)

        val deepSubDec = engine.evaluate("p1.tracker.ad.doubleclick.net")
        assertFalse(deepSubDec.allowed)
    }

    @Test
    fun testDomainBoundarySafety() {
        val rule = DomainRule.create("example.com", RuleType.BLOCK, RuleCategory.ADVERTISING, isWildcard = true)
        engine.addRule(rule!!)

        // Sibling or prefix domains must NOT match
        assertTrue(engine.evaluate("notexample.com").allowed)
        assertTrue(engine.evaluate("fakeexample.com").allowed)
        assertTrue(engine.evaluate("example.com.evil.org").allowed)
    }

    @Test
    fun testAllowlistPrecedence() {
        val blockRule = DomainRule.create("partner.com", RuleType.BLOCK, RuleCategory.TRACKING, isWildcard = true)
        val allowRule = DomainRule.create("api.partner.com", RuleType.ALLOW, RuleCategory.GENERAL, isWildcard = true)
        engine.addRule(blockRule!!)
        engine.addRule(allowRule!!)

        assertFalse(engine.evaluate("partner.com").allowed)
        assertFalse(engine.evaluate("ads.partner.com").allowed)

        // Allowed subdomain overrides
        val allowDec = engine.evaluate("api.partner.com")
        assertTrue(allowDec.allowed)
        assertEquals("allowlist_precedence", allowDec.reason)
    }

    @Test
    fun testCategoryToggle() {
        val telemetryRule = DomainRule.create("telemetry.vendor.com", RuleType.BLOCK, RuleCategory.TELEMETRY)
        engine.addRule(telemetryRule!!)

        // Active
        assertFalse(engine.evaluate("telemetry.vendor.com").allowed)

        // Disable Telemetry
        engine.setCategoryEnabled(RuleCategory.TELEMETRY, false)
        val disabledDec = engine.evaluate("telemetry.vendor.com")
        assertTrue(disabledDec.allowed)
        assertEquals("category_disabled_allow", disabledDec.reason)
    }
}
