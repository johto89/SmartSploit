"""
Blockchain Interface - Interface for blockchain interactions
"""

import os
import logging
from typing import Dict, List, Optional
from web3 import Web3
from .framework import Target

logger = logging.getLogger(__name__)

class BlockchainInterface:
    """Interface for blockchain interactions"""
    
    def __init__(self):
        self.networks: Dict[str, Web3] = {}
        self._init_networks()
        
    def _init_networks(self):
        """Initialize network connections"""
        # Network configurations
        networks_config = {
            "mainnet": os.getenv("MAINNET_RPC", "https://mainnet.infura.io/v3/demo"),
            "sepolia": os.getenv("SEPOLIA_RPC", "https://sepolia.infura.io/v3/demo"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "bsc": os.getenv("BSC_RPC", "https://bsc-dataseed.binance.org/"),
            "local": os.getenv("LOCAL_RPC", "http://127.0.0.1:8545")
        }
        
        for name, rpc_url in networks_config.items():
            try:
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                # Don't check connection for demo URLs
                self.networks[name] = w3
                logger.info(f"Configured {name} network")
            except Exception as e:
                logger.warning(f"Failed to configure {name}: {e}")
                
    def get_contract_info(self, address: str, network: str = "mainnet") -> Optional[Target]:
        """Get contract information from blockchain"""
        if network not in self.networks:
            logger.error(f"Network {network} not available")
            return None
            
        w3 = self.networks[network]
        
        try:
            # For demo purposes, return mock data
            target = Target(
                address=address,
                network=network,
                balance=1000000000000000000  # 1 ETH in wei
            )
            
            return target
            
        except Exception as e:
            logger.error(f"Error getting contract info: {e}")
            return None
            
    def send_transaction(self, transaction_data: Dict, network: str = "mainnet") -> Optional[str]:
        """Send transaction to blockchain"""
        if network not in self.networks:
            return None
            
        try:
            # Return demo transaction hash
            tx_hash = "0x" + "1234567890abcdef" * 4
            logger.info(f"Demo transaction sent: {tx_hash}")
            return tx_hash
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            return None
            
    def get_network_status(self) -> Dict[str, bool]:
        """Get status of all networks"""
        status = {}
        for name, w3 in self.networks.items():
            try:
                # For demo, assume all networks are online
                status[name] = True
            except:
                status[name] = False
        return status
