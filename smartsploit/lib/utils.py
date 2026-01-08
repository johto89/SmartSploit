"""
Utility Functions - Common helper functions
"""

import re
from typing import Optional, Dict, Any
from web3 import Web3

def format_address(address: str) -> str:
    """Format Ethereum address with proper checksum"""
    if not address:
        return ""
    try:
        return Web3.to_checksum_address(address)
    except:
        return address

def wei_to_ether(wei_amount: int) -> float:
    """Convert wei to ether"""
    try:
        return wei_amount / 1e18
    except:
        return 0.0

def ether_to_wei(ether_amount: float) -> int:
    """Convert ether to wei"""
    try:
        return int(ether_amount * 1e18)
    except:
        return 0

def get_contract_name(address: str) -> str:
    """Get contract name from address (simplified)"""
    # In a real implementation, this would query a contract registry
    known_contracts = {
        "0xa0b86a33e6411a3bbe2495e4b8e33c4a5d0a8b7a": "Uniswap V2 Router",
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router 02",
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "Uniswap Token",
        "0xa0b86a33e6411a3bbe2495e4b8e33c4a5d0a8b7a": "WETH Token"
    }
    
    formatted_addr = format_address(address)
    return known_contracts.get(formatted_addr, f"Contract_{formatted_addr[:8]}...")

def validate_ethereum_address(address: str) -> bool:
    """Validate Ethereum address format"""
    if not address:
        return False
    
    # Remove 0x prefix if present
    if address.startswith('0x'):
        address = address[2:]
    
    # Check if it's 40 hex characters
    if len(address) != 40:
        return False
        
    # Check if all characters are hex
    try:
        int(address, 16)
        return True
    except ValueError:
        return False

def parse_transaction_hash(tx_hash: str) -> Optional[str]:
    """Parse and validate transaction hash"""
    if not tx_hash:
        return None
        
    # Remove 0x prefix if present
    if tx_hash.startswith('0x'):
        tx_hash = tx_hash[2:]
    
    # Check if it's 64 hex characters
    if len(tx_hash) != 64:
        return None
        
    try:
        int(tx_hash, 16)
        return f"0x{tx_hash}"
    except ValueError:
        return None

def format_gas_price(gas_price_gwei: float) -> str:
    """Format gas price for display"""
    if gas_price_gwei < 1:
        return f"{gas_price_gwei:.2f} gwei"
    elif gas_price_gwei < 100:
        return f"{gas_price_gwei:.1f} gwei"
    else:
        return f"{gas_price_gwei:.0f} gwei"

def estimate_transaction_cost(gas_limit: int, gas_price_gwei: float) -> Dict[str, Any]:
    """Estimate transaction cost"""
    gas_price_wei = gas_price_gwei * 1e9
    cost_wei = gas_limit * gas_price_wei
    cost_ether = wei_to_ether(cost_wei)
    
    return {
        'gas_limit': gas_limit,
        'gas_price_gwei': gas_price_gwei,
        'cost_wei': int(cost_wei),
        'cost_ether': cost_ether,
        'formatted_cost': f"{cost_ether:.6f} ETH"
    }

def truncate_string(text: str, max_length: int = 50) -> str:
    """Truncate string with ellipsis"""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes:.0f}m {secs:.0f}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours:.0f}h {minutes:.0f}m"

def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely load JSON with default fallback"""
    try:
        import json
        return json.loads(json_str)
    except:
        return default

def generate_exploit_id() -> str:
    """Generate unique exploit ID"""
    import uuid
    return f"exploit_{uuid.uuid4().hex[:8]}"

def calculate_success_rate(successful: int, total: int) -> float:
    """Calculate success rate percentage"""
    if total == 0:
        return 0.0
    return (successful / total) * 100
