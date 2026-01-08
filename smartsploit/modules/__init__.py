"""
SmartSploit Modules
Exploit, auxiliary, payload, and post-exploitation modules
"""

# Module categories
EXPLOIT_MODULES = [
    'exploits.reentrancy.classic_reentrancy',
    'exploits.overflow.integer_overflow', 
    'exploits.access_control.tx_origin',
    'exploits.business_logic.flash_loan_attack',
    'exploits.defi.sandwich_attack'
]

AUXILIARY_MODULES = [
    'auxiliary.scanner.vulnerability_scanner',
    'auxiliary.scanner.contract_info',
    'auxiliary.gather.etherscan_crawler',
    'auxiliary.analysis.static_analyzer'
]

PAYLOAD_MODULES = [
    'payloads.generic.drainer_contract',
    'payloads.specific.erc20_drain'
]

POST_MODULES = [
    'post.persistence.upgrade_hijack',
    'post.exfiltration.token_transfer'
]

__all__ = [
    'EXPLOIT_MODULES',
    'AUXILIARY_MODULES', 
    'PAYLOAD_MODULES',
    'POST_MODULES'
]
