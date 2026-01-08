"""
Auxiliary Modules
Information gathering, scanning, and analysis modules
"""

# Available auxiliary modules
SCANNER_MODULES = [
    'contract_info',
    'network_scanner', 
    'vulnerability_scanner'
]

GATHER_MODULES = [
    'etherscan_crawler',
    'github_crawler'
]

ANALYSIS_MODULES = [
    'static_analyzer',
    'dynamic_analyzer'
]

__all__ = [
    'SCANNER_MODULES',
    'GATHER_MODULES',
    'ANALYSIS_MODULES'
]
