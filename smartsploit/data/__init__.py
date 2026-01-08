"""
SmartSploit Data Components
Training data, signatures, and reference data for the framework
"""

import os
import json
import pandas as pd
from typing import Dict, List, Optional

def load_training_data(file_path: str = None) -> Optional[pd.DataFrame]:
    """Load ML training data from CSV or JSON"""
    if not file_path:
        file_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    
    if not os.path.exists(file_path):
        return None
    
    try:
        if file_path.endswith('.csv'):
            return pd.read_csv(file_path)
        elif file_path.endswith('.json'):
            return pd.read_json(file_path)
        else:
            return None
    except Exception:
        return None

def load_vulnerability_signatures() -> Dict[str, List[str]]:
    """Load vulnerability signatures database"""
    return {
        'reentrancy': [
            '0xa9059cbb',  # transfer(address,uint256)
            '0x2e1a7d4d',  # withdraw(uint256)
            '0x3ccfd60b',  # withdraw()
        ],
        'overflow': [
            '0x095ea7b3',  # approve(address,uint256)
            '0xa9059cbb',  # transfer(address,uint256)
            '0x23b872dd',  # transferFrom(address,address,uint256)
        ],
        'access_control': [
            '0x8da5cb5b',  # owner()
            '0xf2fde38b',  # transferOwnership(address)
            '0x715018a6',  # renounceOwnership()
        ]
    }

def load_known_contracts() -> Dict[str, Dict]:
    """Load known contract addresses and metadata"""
    return {
        '0xa0b86a33e6411a3bbe2495e4b8e33c4a5d0a8b7a': {
            'name': 'Uniswap V2 Router',
            'type': 'DEX',
            'risk_level': 'LOW',
            'verified': True
        },
        '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': {
            'name': 'Uniswap V2 Router 02',
            'type': 'DEX',
            'risk_level': 'LOW',
            'verified': True
        },
        '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984': {
            'name': 'Uniswap Token',
            'type': 'ERC20',
            'risk_level': 'LOW',
            'verified': True
        }
    }

def get_vulnerability_wordlist() -> List[str]:
    """Get common vulnerability-related function names"""
    return [
        'withdraw', 'transfer', 'approve', 'mint', 'burn',
        'deposit', 'stake', 'unstake', 'claim', 'redeem',
        'execute', 'call', 'delegatecall', 'selfdestruct',
        'destroy', 'kill', 'emergency', 'pause', 'unpause',
        'setOwner', 'transferOwnership', 'renounceOwnership',
        'addAdmin', 'removeAdmin', 'grantRole', 'revokeRole'
    ]

__all__ = [
    'load_training_data',
    'load_vulnerability_signatures',
    'load_known_contracts',
    'get_vulnerability_wordlist'
]
