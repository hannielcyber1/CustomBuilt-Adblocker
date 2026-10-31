package com.shieldnet.app.engine

class DomainTrieNode {
    val children: MutableMap<String, DomainTrieNode> = HashMap()
    var rule: DomainRule? = null
    var isTerminal: Boolean = false
}

class DomainTrie {
    val root = DomainTrieNode()
    var size: Int = 0
        private set

    fun insert(rule: DomainRule) {
        val labels = rule.pattern.split(".").reversed()
        var node = root
        for (label in labels) {
            node = node.children.getOrPut(label) { DomainTrieNode() }
        }
        node.isTerminal = true
        node.rule = rule
        size++
    }

    fun match(reversedLabels: List<String>): DomainRule? {
        var node = root
        for (label in reversedLabels) {
            val child = node.children[label] ?: return null
            node = child
            if (node.isTerminal && node.rule?.isWildcard == true) {
                return node.rule
            }
        }
        return if (node.isTerminal) node.rule else null
    }

    fun clear() {
        root.children.clear()
        root.rule = null
        root.isTerminal = false
        size = 0
    }
}
