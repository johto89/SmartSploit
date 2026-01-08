"""
Etherscan Intelligence Gathering Module
SmartSploit Framework - Crawls Etherscan for contract and transaction intelligence
"""

from smartsploit.lib.base_module import BaseAuxiliary, ModuleInfo
import requests
import json
import time
import logging

logger = logging.getLogger(__name__)

class EtherscanCrawler(BaseAuxiliary):
    """Gathers intelligence from Etherscan API and web interface"""
    
    def __init__(self):
        super().__init__()
        self.name = "Etherscan Intelligence Crawler"
        self.description = "Crawls Etherscan for contract source code, transactions, and metadata"
        self.author = "SmartSploit Team"
        
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "https://etherscan.io/apis",
                "https://docs.etherscan.io/",
                "Blockchain Intelligence Gathering"
            ],
            severity="info",
            targets=["Smart contracts", "Transaction history", "Token information", "Address analytics"]
        )
        
        self.options = {
            "TARGET_ADDRESS": {"value": "", "required": True, "description": "Target contract or address"},
            "API_KEY": {"value": "", "required": False, "description": "Etherscan API key"},
            "NETWORK": {"value": "mainnet", "required": False, "description": "Network (mainnet, goerli, sepolia)"},
            "CRAWL_DEPTH": {"value": "basic", "required": False, "description": "Crawl depth (basic, extended, deep)"},
            "MAX_TRANSACTIONS": {"value": "100", "required": False, "description": "Maximum transactions to analyze"},
            "INCLUDE_TOKENS": {"value": "true", "required": False, "description": "Include token information"},
            "INCLUDE_INTERNAL": {"value": "false", "required": False, "description": "Include internal transactions"},
            "OUTPUT_FORMAT": {"value": "json", "required": False, "description": "Output format (json, csv)"},
            "SAVE_RESULTS": {"value": "true", "required": False, "description": "Save results to file"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        if not self.options["TARGET_ADDRESS"]["value"]:
            logger.error("Target address is required")
            return False
        return True
        
    def get_etherscan_base_url(self) -> str:
        """Get Etherscan base URL for network"""
        network = self.options["NETWORK"]["value"]
        urls = {
            "mainnet": "https://api.etherscan.io/api",
            "goerli": "https://api-goerli.etherscan.io/api",
            "sepolia": "https://api-sepolia.etherscan.io/api"
        }
        return urls.get(network, urls["mainnet"])
        
    def make_api_request(self, params: dict) -> dict:
        """Make API request with rate limiting"""
        try:
            base_url = self.get_etherscan_base_url()
            api_key = self.options["API_KEY"]["value"]
            
            if api_key:
                params["apikey"] = api_key
                
            response = requests.get(base_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "1":
                    return {"success": True, "data": data["result"]}
                else:
                    return {"success": False, "error": data.get("message", "API error")}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
            # Rate limiting
            time.sleep(0.2)
            
        except Exception as e:
            logger.error(f"API request failed: {e}")
            return {"success": False, "error": str(e)}
            
    def get_contract_source_code(self, address: str) -> dict:
        """Get contract source code and metadata"""
        try:
            params = {
                "module": "contract",
                "action": "getsourcecode",
                "address": address
            }
            
            result = self.make_api_request(params)
            
            if result["success"] and result["data"]:
                source_data = result["data"][0]
                
                return {
                    "contract_name": source_data.get("ContractName", ""),
                    "compiler_version": source_data.get("CompilerVersion", ""),
                    "optimization_used": source_data.get("OptimizationUsed", ""),
                    "optimization_runs": source_data.get("Runs", ""),
                    "constructor_arguments": source_data.get("ConstructorArguments", ""),
                    "evm_version": source_data.get("EVMVersion", ""),
                    "library": source_data.get("Library", ""),
                    "license_type": source_data.get("LicenseType", ""),
                    "proxy": source_data.get("Proxy", ""),
                    "implementation": source_data.get("Implementation", ""),
                    "swarm_source": source_data.get("SwarmSource", ""),
                    "source_code": source_data.get("SourceCode", ""),
                    "abi": source_data.get("ABI", "")
                }
            else:
                return {"error": result.get("error", "Failed to get source code")}
                
        except Exception as e:
            logger.error(f"Source code retrieval failed: {e}")
            return {"error": str(e)}
            
    def get_transaction_history(self, address: str) -> dict:
        """Get transaction history for address"""
        try:
            max_txs = int(self.options["MAX_TRANSACTIONS"]["value"])
            
            params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": max_txs,
                "sort": "desc"
            }
            
            result = self.make_api_request(params)
            
            if result["success"]:
                transactions = result["data"]
                
                # Analyze transaction patterns
                analysis = {
                    "total_transactions": len(transactions),
                    "unique_addresses": set(),
                    "function_calls": {},
                    "value_analysis": {
                        "total_value_in": 0,
                        "total_value_out": 0,
                        "large_transactions": []
                    },
                    "gas_analysis": {
                        "avg_gas_used": 0,
                        "max_gas_used": 0,
                        "failed_transactions": 0
                    },
                    "time_analysis": {
                        "first_transaction": None,
                        "last_transaction": None,
                        "activity_periods": []
                    }
                }
                
                total_gas = 0
                
                for tx in transactions:
                    # Track unique addresses
                    analysis["unique_addresses"].add(tx.get("from", ""))
                    analysis["unique_addresses"].add(tx.get("to", ""))
                    
                    # Function call analysis
                    input_data = tx.get("input", "")
                    if len(input_data) >= 10:
                        func_sig = input_data[:10]
                        analysis["function_calls"][func_sig] = analysis["function_calls"].get(func_sig, 0) + 1
                        
                    # Value analysis
                    value = int(tx.get("value", "0"))
                    if tx.get("to", "").lower() == address.lower():
                        analysis["value_analysis"]["total_value_in"] += value
                    else:
                        analysis["value_analysis"]["total_value_out"] += value
                        
                    if value > 10**18:  # > 1 ETH
                        analysis["value_analysis"]["large_transactions"].append({
                            "hash": tx.get("hash"),
                            "value": value / 10**18,
                            "timestamp": tx.get("timeStamp")
                        })
                        
                    # Gas analysis
                    gas_used = int(tx.get("gasUsed", "0"))
                    total_gas += gas_used
                    analysis["gas_analysis"]["max_gas_used"] = max(analysis["gas_analysis"]["max_gas_used"], gas_used)
                    
                    if tx.get("isError") == "1":
                        analysis["gas_analysis"]["failed_transactions"] += 1
                        
                    # Time analysis
                    timestamp = int(tx.get("timeStamp", "0"))
                    if not analysis["time_analysis"]["first_transaction"]:
                        analysis["time_analysis"]["first_transaction"] = timestamp
                    analysis["time_analysis"]["last_transaction"] = timestamp
                    
                # Calculate averages
                if transactions:
                    analysis["gas_analysis"]["avg_gas_used"] = total_gas // len(transactions)
                    analysis["unique_addresses"] = len(analysis["unique_addresses"])
                    
                return {
                    "transactions": transactions,
                    "analysis": analysis
                }
            else:
                return {"error": result.get("error", "Failed to get transactions")}
                
        except Exception as e:
            logger.error(f"Transaction history retrieval failed: {e}")
            return {"error": str(e)}
            
    def get_token_information(self, address: str) -> dict:
        """Get token information if address is a token contract"""
        try:
            # Get token info
            token_info = {}
            
            # Token supply
            params = {
                "module": "stats",
                "action": "tokensupply",
                "contractaddress": address
            }
            
            result = self.make_api_request(params)
            if result["success"]:
                token_info["total_supply"] = result["data"]
                
            # Token holders (top holders)
            params = {
                "module": "token",
                "action": "tokenholderlist",
                "contractaddress": address,
                "page": 1,
                "offset": 20
            }
            
            result = self.make_api_request(params)
            if result["success"]:
                token_info["top_holders"] = result["data"]
                
            # Token transfers
            params = {
                "module": "account",
                "action": "tokentx",
                "contractaddress": address,
                "page": 1,
                "offset": 100,
                "sort": "desc"
            }
            
            result = self.make_api_request(params)
            if result["success"]:
                transfers = result["data"]
                
                # Analyze transfers
                transfer_analysis = {
                    "total_transfers": len(transfers),
                    "unique_addresses": set(),
                    "large_transfers": [],
                    "recent_activity": []
                }
                
                for transfer in transfers[:10]:  # Recent transfers
                    transfer_analysis["unique_addresses"].add(transfer.get("from", ""))
                    transfer_analysis["unique_addresses"].add(transfer.get("to", ""))
                    
                    value = int(transfer.get("value", "0"))
                    decimals = int(transfer.get("tokenDecimal", "18"))
                    actual_value = value / (10**decimals)
                    
                    if actual_value > 1000:  # Large transfer
                        transfer_analysis["large_transfers"].append({
                            "hash": transfer.get("hash"),
                            "from": transfer.get("from"),
                            "to": transfer.get("to"),
                            "value": actual_value,
                            "timestamp": transfer.get("timeStamp")
                        })
                        
                    transfer_analysis["recent_activity"].append({
                        "hash": transfer.get("hash"),
                        "from": transfer.get("from"),
                        "to": transfer.get("to"),
                        "value": actual_value,
                        "timestamp": transfer.get("timeStamp")
                    })
                    
                transfer_analysis["unique_addresses"] = len(transfer_analysis["unique_addresses"])
                token_info["transfer_analysis"] = transfer_analysis
                
            return token_info
            
        except Exception as e:
            logger.error(f"Token information retrieval failed: {e}")
            return {"error": str(e)}
            
    def get_contract_analytics(self, address: str) -> dict:
        """Get additional contract analytics"""
        try:
            analytics = {
                "balance": "0",
                "transaction_count": 0,
                "contract_creation": {},
                "verified": False
            }
            
            # Get balance
            params = {
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest"
            }
            
            result = self.make_api_request(params)
            if result["success"]:
                balance = int(result["data"])
                analytics["balance"] = balance / 10**18  # Convert to ETH
                
            # Get transaction count
            params = {
                "module": "proxy",
                "action": "eth_getTransactionCount",
                "address": address,
                "tag": "latest"
            }
            
            result = self.make_api_request(params)
            if result["success"]:
                analytics["transaction_count"] = int(result["data"], 16)
                
            # Get contract creation info
            params = {
                "module": "contract",
                "action": "getcontractcreation",
                "contractaddresses": address
            }
            
            result = self.make_api_request(params)
            if result["success"] and result["data"]:
                creation_data = result["data"][0]
                analytics["contract_creation"] = {
                    "creator": creation_data.get("contractCreator"),
                    "creation_tx": creation_data.get("txHash")
                }
                
            return analytics
            
        except Exception as e:
            logger.error(f"Contract analytics failed: {e}")
            return {"error": str(e)}
            
    def analyze_security_patterns(self, source_code: str) -> dict:
        """Analyze source code for security patterns"""
        try:
            if not source_code:
                return {"error": "No source code available"}
                
            security_analysis = {
                "vulnerabilities": [],
                "security_features": [],
                "external_calls": [],
                "modifiers": [],
                "events": []
            }
            
            code_lower = source_code.lower()
            
            # Check for vulnerabilities
            vulnerability_patterns = [
                ("tx.origin", "tx.origin usage detected - potential phishing vulnerability"),
                ("block.timestamp", "Timestamp dependence detected"),
                ("blockhash", "Blockhash usage - potential randomness issues"),
                ("delegatecall", "Delegatecall usage - potential security risk"),
                ("selfdestruct", "Selfdestruct functionality present"),
                ("suicide", "Deprecated suicide function"),
                ("call.value", "Low-level call with value transfer"),
                ("send(", "Use of send() function - check return value"),
                ("transfer(", "Transfer function usage")
            ]
            
            for pattern, description in vulnerability_patterns:
                if pattern in code_lower:
                    security_analysis["vulnerabilities"].append({
                        "pattern": pattern,
                        "description": description,
                        "severity": "medium" if pattern in ["tx.origin", "delegatecall"] else "low"
                    })
                    
            # Check for security features
            security_features = [
                ("require(", "Require statements for validation"),
                ("assert(", "Assert statements for invariants"),
                ("revert(", "Explicit revert statements"),
                ("onlyowner", "Owner-only access control"),
                ("modifier", "Function modifiers"),
                ("safemath", "SafeMath library usage"),
                ("openzeppelin", "OpenZeppelin library usage"),
                ("reentrancyguard", "Reentrancy protection")
            ]
            
            for pattern, description in security_features:
                if pattern in code_lower:
                    security_analysis["security_features"].append({
                        "pattern": pattern,
                        "description": description
                    })
                    
            # Extract events
            import re
            event_pattern = r'event\s+(\w+)\s*\('
            events = re.findall(event_pattern, source_code, re.IGNORECASE)
            security_analysis["events"] = list(set(events))
            
            # Extract modifiers
            modifier_pattern = r'modifier\s+(\w+)\s*\('
            modifiers = re.findall(modifier_pattern, source_code, re.IGNORECASE)
            security_analysis["modifiers"] = list(set(modifiers))
            
            return security_analysis
            
        except Exception as e:
            logger.error(f"Security pattern analysis failed: {e}")
            return {"error": str(e)}
            
    def save_results_to_file(self, results: dict) -> str:
        """Save crawl results to file"""
        try:
            output_format = self.options["OUTPUT_FORMAT"]["value"]
            address = self.options["TARGET_ADDRESS"]["value"]
            filename = f"etherscan_crawl_{address[:10]}_{int(time.time())}"
            
            if output_format == "json":
                filename += ".json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            else:  # csv
                filename += ".csv"
                with open(filename, 'w') as f:
                    f.write("Category,Key,Value\n")
                    
                    def write_dict(d, prefix=""):
                        for key, value in d.items():
                            if isinstance(value, dict):
                                write_dict(value, f"{prefix}{key}.")
                            elif isinstance(value, list):
                                f.write(f"list,{prefix}{key},{len(value)}\n")
                            else:
                                f.write(f"value,{prefix}{key},{value}\n")
                                
                    write_dict(results)
                    
            logger.info(f"Results saved to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return ""
            
    def run(self) -> dict:
        """Main execution method"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Starting Etherscan intelligence gathering...")
        
        try:
            address = self.options["TARGET_ADDRESS"]["value"]
            crawl_depth = self.options["CRAWL_DEPTH"]["value"]
            
            results = {
                "target_address": address,
                "network": self.options["NETWORK"]["value"],
                "crawl_timestamp": int(time.time()),
                "crawl_depth": crawl_depth
            }
            
            # Basic information gathering
            logger.info("Gathering basic contract information...")
            results["contract_analytics"] = self.get_contract_analytics(address)
            
            # Get source code
            logger.info("Retrieving contract source code...")
            source_result = self.get_contract_source_code(address)
            results["source_code"] = source_result
            
            if not source_result.get("error"):
                results["verified_contract"] = True
                
                # Security analysis of source code
                logger.info("Analyzing source code for security patterns...")
                results["security_analysis"] = self.analyze_security_patterns(source_result.get("source_code", ""))
            else:
                results["verified_contract"] = False
                
            # Transaction history
            logger.info("Analyzing transaction history...")
            results["transaction_history"] = self.get_transaction_history(address)
            
            # Token information (if applicable)
            if self.options["INCLUDE_TOKENS"]["value"].lower() == "true":
                logger.info("Gathering token information...")
                results["token_info"] = self.get_token_information(address)
                
            # Extended analysis for deeper crawls
            if crawl_depth in ["extended", "deep"]:
                logger.info("Performing extended analysis...")
                
                # Analyze related contracts
                tx_data = results.get("transaction_history", {})
                if "analysis" in tx_data:
                    unique_addresses = tx_data["analysis"].get("unique_addresses", 0)
                    results["network_analysis"] = {
                        "connected_addresses": unique_addresses,
                        "interaction_complexity": "high" if unique_addresses > 50 else "medium" if unique_addresses > 10 else "low"
                    }
                    
            # Save results if requested
            if self.options["SAVE_RESULTS"]["value"].lower() == "true":
                filename = self.save_results_to_file(results)
                results["output_file"] = filename
                
            logger.info("Etherscan intelligence gathering completed")
            
            return {
                "result": "success",
                "message": f"Intelligence gathering completed for {address}",
                "data": results
            }
            
        except Exception as e:
            logger.error(f"Etherscan crawler failed: {e}")
            return {"result": "error", "message": str(e)}