"""
Network Scanner Module
SmartSploit Framework - Blockchain network analysis and reconnaissance
"""

from smartsploit.lib.base_module import BaseAuxiliary, ModuleInfo
from smartsploit.core.blockchain_interface import get_web3_connection
from web3 import Web3
import requests
import json
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class NetworkScanner(BaseAuxiliary):
    """Network scanning and reconnaissance module for blockchain networks"""
    
    def __init__(self):
        super().__init__()
        self.name = "Network Scanner"
        self.description = "Scans blockchain networks for targets and reconnaissance"
        self.author = "SmartSploit Team"
        
        # Set module info
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "https://ethereum.org/en/developers/docs/apis/json-rpc/",
                "https://docs.web3py.org/",
                "Blockchain Network Analysis"
            ],
            severity="info",
            targets=["Ethereum networks", "RPC endpoints", "Contract addresses"]
        )
        
        # Module options
        self.options = {
            "RPC_URL": {"value": "http://localhost:8545", "required": True, "description": "Primary RPC endpoint"},
            "SCAN_TYPE": {"value": "network", "required": True, "description": "Scan type (network, contracts, blocks)"},
            "START_BLOCK": {"value": "latest", "required": False, "description": "Starting block number"},
            "BLOCK_COUNT": {"value": "100", "required": False, "description": "Number of blocks to scan"},
            "CONTRACT_FILTER": {"value": "", "required": False, "description": "Contract address filter"},
            "THREAD_COUNT": {"value": "5", "required": False, "description": "Number of scanning threads"},
            "SAVE_RESULTS": {"value": "true", "required": False, "description": "Save scan results"},
            "OUTPUT_FILE": {"value": "network_scan.json", "required": False, "description": "Output filename"},
            "SCAN_CONTRACTS": {"value": "true", "required": False, "description": "Include contract scanning"},
            "SCAN_TRANSACTIONS": {"value": "false", "required": False, "description": "Include transaction analysis"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        try:
            rpc_url = self.options["RPC_URL"]["value"]
            if not rpc_url:
                logger.error("RPC URL is required")
                return False
                
            # Test connection
            w3 = get_web3_connection(rpc_url)
            if not w3.is_connected():
                logger.error("Failed to connect to RPC endpoint")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Requirements check failed: {e}")
            return False
            
    def get_network_info(self, w3) -> dict:
        """Get basic network information"""
        try:
            info = {
                "chain_id": w3.eth.chain_id,
                "latest_block": w3.eth.block_number,
                "gas_price": w3.eth.gas_price,
                "peer_count": 0,
                "syncing": w3.eth.syncing,
                "network_type": "unknown"
            }
            
            # Try to get peer count (may not be available on all networks)
            try:
                info["peer_count"] = w3.net.peer_count
            except:
                info["peer_count"] = "unavailable"
                
            # Determine network type based on chain ID
            chain_names = {
                1: "Ethereum Mainnet",
                3: "Ropsten Testnet", 
                4: "Rinkeby Testnet",
                5: "Goerli Testnet",
                11155111: "Sepolia Testnet",
                137: "Polygon Mainnet",
                80001: "Polygon Mumbai",
                56: "BSC Mainnet",
                97: "BSC Testnet",
                1337: "Local Development"
            }
            
            info["network_type"] = chain_names.get(info["chain_id"], f"Unknown (Chain ID: {info['chain_id']})")
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get network info: {e}")
            return {"error": str(e)}
            
    def scan_block_range(self, w3, start_block: int, count: int) -> dict:
        """Scan a range of blocks for analysis"""
        try:
            results = {
                "blocks_scanned": 0,
                "transactions_found": 0,
                "contracts_found": [],
                "gas_usage": [],
                "block_times": [],
                "large_transactions": []
            }
            
            logger.info(f"Scanning blocks {start_block} to {start_block + count}")
            
            for block_num in range(start_block, start_block + count):
                try:
                    block = w3.eth.get_block(block_num, full_transactions=True)
                    results["blocks_scanned"] += 1
                    
                    # Analyze block
                    results["gas_usage"].append({
                        "block": block_num,
                        "gas_used": block.gasUsed,
                        "gas_limit": block.gasLimit
                    })
                    
                    # Calculate block time
                    if results["blocks_scanned"] > 1:
                        prev_block = w3.eth.get_block(block_num - 1)
                        block_time = block.timestamp - prev_block.timestamp
                        results["block_times"].append(block_time)
                        
                    # Analyze transactions
                    for tx in block.transactions:
                        results["transactions_found"] += 1
                        
                        # Check for contract creation
                        if tx.to is None:
                            receipt = w3.eth.get_transaction_receipt(tx.hash)
                            if receipt.contractAddress:
                                results["contracts_found"].append({
                                    "address": receipt.contractAddress,
                                    "creator": tx["from"],
                                    "block": block_num,
                                    "gas_used": receipt.gasUsed
                                })
                                
                        # Check for large value transactions
                        if tx.value > Web3.to_wei(1, 'ether'):
                            results["large_transactions"].append({
                                "hash": tx.hash.hex(),
                                "from": tx["from"],
                                "to": tx.to,
                                "value": Web3.from_wei(tx.value, 'ether'),
                                "block": block_num
                            })
                            
                except Exception as e:
                    logger.warning(f"Error scanning block {block_num}: {e}")
                    continue
                    
            return results
            
        except Exception as e:
            logger.error(f"Block range scan failed: {e}")
            return {"error": str(e)}
            
    def scan_contract_addresses(self, w3, addresses: list) -> dict:
        """Scan specific contract addresses"""
        try:
            results = {
                "contracts_analyzed": 0,
                "active_contracts": [],
                "inactive_contracts": [],
                "total_balance": 0
            }
            
            def scan_single_contract(address):
                try:
                    # Get contract info
                    code = w3.eth.get_code(address)
                    balance = w3.eth.get_balance(address)
                    tx_count = w3.eth.get_transaction_count(address)
                    
                    contract_info = {
                        "address": address,
                        "has_code": len(code) > 2,
                        "balance": Web3.from_wei(balance, 'ether'),
                        "transaction_count": tx_count,
                        "code_size": len(code)
                    }
                    
                    # Classify as active/inactive
                    if contract_info["has_code"] and (contract_info["balance"] > 0 or contract_info["transaction_count"] > 0):
                        return ("active", contract_info)
                    else:
                        return ("inactive", contract_info)
                        
                except Exception as e:
                    logger.warning(f"Error scanning contract {address}: {e}")
                    return ("error", {"address": address, "error": str(e)})
                    
            # Use threading for faster scanning
            thread_count = int(self.options["THREAD_COUNT"]["value"])
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {executor.submit(scan_single_contract, addr): addr for addr in addresses}
                
                for future in as_completed(futures):
                    try:
                        status, contract_info = future.result()
                        results["contracts_analyzed"] += 1
                        
                        if status == "active":
                            results["active_contracts"].append(contract_info)
                            results["total_balance"] += float(contract_info["balance"])
                        elif status == "inactive":
                            results["inactive_contracts"].append(contract_info)
                            
                    except Exception as e:
                        logger.warning(f"Contract scan error: {e}")
                        
            return results
            
        except Exception as e:
            logger.error(f"Contract address scan failed: {e}")
            return {"error": str(e)}
            
    def discover_rpc_endpoints(self) -> dict:
        """Discover and test additional RPC endpoints"""
        try:
            # Common RPC endpoints for different networks
            endpoints = {
                "mainnet": [
                    "https://mainnet.infura.io/v3/",
                    "https://eth-mainnet.alchemyapi.io/v2/",
                    "https://rpc.ankr.com/eth",
                    "https://ethereum.publicnode.com"
                ],
                "polygon": [
                    "https://polygon-rpc.com/",
                    "https://rpc-mainnet.matic.network",
                    "https://rpc.ankr.com/polygon"
                ],
                "bsc": [
                    "https://bsc-dataseed.binance.org/",
                    "https://rpc.ankr.com/bsc"
                ]
            }
            
            results = {
                "tested_endpoints": 0,
                "working_endpoints": [],
                "failed_endpoints": [],
                "response_times": {}
            }
            
            for network, urls in endpoints.items():
                for url in urls:
                    try:
                        results["tested_endpoints"] += 1
                        start_time = time.time()
                        
                        # Test basic connectivity
                        if url.startswith("https://mainnet.infura.io") or url.startswith("https://eth-mainnet.alchemyapi.io"):
                            # These require API keys, skip for demo
                            results["failed_endpoints"].append({
                                "url": url,
                                "reason": "API key required"
                            })
                            continue
                            
                        # Try to connect
                        test_data = {
                            "jsonrpc": "2.0",
                            "method": "eth_blockNumber",
                            "params": [],
                            "id": 1
                        }
                        
                        response = requests.post(url, json=test_data, timeout=5)
                        response_time = time.time() - start_time
                        
                        if response.status_code == 200:
                            data = response.json()
                            if "result" in data:
                                results["working_endpoints"].append({
                                    "url": url,
                                    "network": network,
                                    "latest_block": int(data["result"], 16),
                                    "response_time": response_time
                                })
                                results["response_times"][url] = response_time
                            else:
                                results["failed_endpoints"].append({
                                    "url": url,
                                    "reason": "Invalid response format"
                                })
                        else:
                            results["failed_endpoints"].append({
                                "url": url,
                                "reason": f"HTTP {response.status_code}"
                            })
                            
                    except Exception as e:
                        results["failed_endpoints"].append({
                            "url": url,
                            "reason": str(e)
                        })
                        
            return results
            
        except Exception as e:
            logger.error(f"RPC endpoint discovery failed: {e}")
            return {"error": str(e)}
            
    def generate_target_list(self, scan_results: dict) -> list:
        """Generate a list of potential targets from scan results"""
        try:
            targets = []
            
            # Add contracts found during block scanning
            for contract in scan_results.get("block_scan", {}).get("contracts_found", []):
                targets.append({
                    "type": "contract",
                    "address": contract["address"],
                    "reason": "newly_deployed",
                    "block": contract["block"]
                })
                
            # Add active contracts
            for contract in scan_results.get("contract_scan", {}).get("active_contracts", []):
                if contract["balance"] > 1:  # Contracts with significant balance
                    targets.append({
                        "type": "high_value_contract",
                        "address": contract["address"],
                        "reason": f"high_balance_{contract['balance']}_ETH",
                        "balance": contract["balance"]
                    })
                    
            # Add addresses from large transactions
            for tx in scan_results.get("block_scan", {}).get("large_transactions", []):
                if tx["to"]:  # Not contract creation
                    targets.append({
                        "type": "high_value_address",
                        "address": tx["to"],
                        "reason": f"received_{tx['value']}_ETH",
                        "transaction": tx["hash"]
                    })
                    
            return targets
            
        except Exception as e:
            logger.error(f"Target list generation failed: {e}")
            return []
            
    def save_scan_results(self, results: dict) -> str:
        """Save scan results to file"""
        try:
            filename = self.options["OUTPUT_FILE"]["value"]
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
                
            logger.info(f"Scan results saved to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return ""
            
    def run(self) -> dict:
        """Main execution method"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Starting network scan...")
        
        try:
            w3 = get_web3_connection(self.options["RPC_URL"]["value"])
            scan_type = self.options["SCAN_TYPE"]["value"]
            
            results = {
                "scan_timestamp": time.time(),
                "scan_type": scan_type,
                "network_info": {},
                "targets_discovered": []
            }
            
            # Get basic network information
            logger.info("Gathering network information...")
            results["network_info"] = self.get_network_info(w3)
            
            if scan_type == "network":
                # Full network reconnaissance
                logger.info("Performing network reconnaissance...")
                results["rpc_discovery"] = self.discover_rpc_endpoints()
                
            elif scan_type == "blocks":
                # Block range scanning
                start_block_str = self.options["START_BLOCK"]["value"]
                if start_block_str == "latest":
                    start_block = w3.eth.block_number - int(self.options["BLOCK_COUNT"]["value"])
                else:
                    start_block = int(start_block_str)
                    
                count = int(self.options["BLOCK_COUNT"]["value"])
                
                logger.info(f"Scanning {count} blocks starting from {start_block}...")
                results["block_scan"] = self.scan_block_range(w3, start_block, count)
                
            elif scan_type == "contracts":
                # Contract scanning
                contract_filter = self.options["CONTRACT_FILTER"]["value"]
                if contract_filter:
                    addresses = [addr.strip() for addr in contract_filter.split(",")]
                    logger.info(f"Scanning {len(addresses)} contract addresses...")
                    results["contract_scan"] = self.scan_contract_addresses(w3, addresses)
                else:
                    logger.warning("No contract addresses specified for contract scan")
                    
            # Generate target list from results
            if scan_type in ["blocks", "contracts"]:
                logger.info("Generating target list...")
                results["targets_discovered"] = self.generate_target_list(results)
                
            # Save results if requested
            if self.options["SAVE_RESULTS"]["value"].lower() == "true":
                filename = self.save_scan_results(results)
                results["output_file"] = filename
                
            logger.info("Network scan completed successfully")
            return {
                "result": "success",
                "message": f"Network scan completed ({scan_type})",
                "data": results
            }
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return {
                "result": "error",
                "message": f"Scan failed: {str(e)}"
            }