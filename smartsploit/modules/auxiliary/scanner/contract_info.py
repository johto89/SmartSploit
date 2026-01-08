"""
Contract Information Gathering Module
SmartSploit Framework - Comprehensive contract analysis and information extraction
"""

from smartsploit.lib.base_module import BaseAuxiliary, ModuleInfo
from smartsploit.core.blockchain_interface import get_web3_connection
from web3 import Web3
import json
import requests
import logging

logger = logging.getLogger(__name__)

class ContractInfoScanner(BaseAuxiliary):
    """Contract information gathering and analysis module"""
    
    def __init__(self):
        super().__init__()
        self.name = "Contract Info Scanner"
        self.description = "Gathers comprehensive information about smart contracts"
        self.author = "SmartSploit Team"
        
        # Set module info
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "https://etherscan.io/apis",
                "https://docs.web3py.org/",
                "Smart Contract Analysis Best Practices"
            ],
            severity="info",
            targets=["All smart contracts", "Contract addresses", "Deployed bytecode"]
        )
        
        # Module options
        self.options = {
            "TARGET_CONTRACT": {"value": "", "required": True, "description": "Target contract address"},
            "RPC_URL": {"value": "http://localhost:8545", "required": True, "description": "Blockchain RPC endpoint"},
            "ETHERSCAN_API_KEY": {"value": "", "required": False, "description": "Etherscan API key for enhanced data"},
            "NETWORK": {"value": "mainnet", "required": False, "description": "Network (mainnet, goerli, sepolia)"},
            "DEEP_ANALYSIS": {"value": "false", "required": False, "description": "Enable deep bytecode analysis"},
            "SAVE_RESULTS": {"value": "true", "required": False, "description": "Save results to file"},
            "OUTPUT_FORMAT": {"value": "json", "required": False, "description": "Output format (json, csv, txt)"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        target = self.options["TARGET_CONTRACT"]["value"]
        if not target:
            logger.error("Target contract address is required")
            return False
            
        if not Web3.is_address(target):
            logger.error("Invalid contract address format")
            return False
            
        return True
        
    def get_basic_contract_info(self, w3, address: str) -> dict:
        """Get basic contract information"""
        try:
            info = {
                "address": address,
                "balance": None,
                "code_size": 0,
                "is_contract": False,
                "transaction_count": 0
            }
            
            # Get balance
            balance = w3.eth.get_balance(address)
            info["balance"] = Web3.from_wei(balance, 'ether')
            
            # Get code
            code = w3.eth.get_code(address)
            info["code_size"] = len(code)
            info["is_contract"] = len(code) > 2
            
            # Get transaction count
            info["transaction_count"] = w3.eth.get_transaction_count(address)
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get basic contract info: {e}")
            return {"error": str(e)}
            
    def analyze_bytecode(self, w3, address: str) -> dict:
        """Analyze contract bytecode for patterns and functions"""
        try:
            code = w3.eth.get_code(address)
            
            if len(code) <= 2:
                return {"error": "No contract code found"}
                
            analysis = {
                "bytecode_length": len(code),
                "functions_detected": [],
                "security_patterns": [],
                "external_calls": [],
                "storage_operations": [],
                "events": []
            }
            
            code_hex = code.hex()
            
            # Detect common function signatures
            function_signatures = {
                "60606040": "Solidity constructor pattern",
                "6080604052": "Modern Solidity constructor",
                "63c6888fa1": "balanceOf(address)",
                "63a9059cbb": "transfer(address,uint256)",
                "6370a08231": "totalSupply()",
                "638da5cb5b": "owner()",
                "63f2fde38b": "transferOwnership(address)"
            }
            
            for sig, desc in function_signatures.items():
                if sig in code_hex:
                    analysis["functions_detected"].append({
                        "signature": sig,
                        "description": desc
                    })
                    
            # Detect security-relevant patterns
            security_patterns = {
                "call": "External call detected",
                "delegatecall": "Delegatecall detected - high risk",
                "selfdestruct": "Self-destruct capability",
                "suicide": "Suicide instruction (deprecated)",
                "sstore": "Storage write operation",
                "sload": "Storage read operation",
                "revert": "Revert instruction",
                "assert": "Assert instruction"
            }
            
            for pattern, desc in security_patterns.items():
                # Convert pattern to bytecode if needed
                if pattern in code_hex.lower():
                    analysis["security_patterns"].append({
                        "pattern": pattern,
                        "description": desc
                    })
                    
            # Detect events (LOG instructions)
            log_opcodes = ["a0", "a1", "a2", "a3", "a4"]  # LOG0-LOG4
            for i, opcode in enumerate(log_opcodes):
                if opcode in code_hex.lower():
                    analysis["events"].append(f"LOG{i} event detected")
                    
            return analysis
            
        except Exception as e:
            logger.error(f"Bytecode analysis failed: {e}")
            return {"error": str(e)}
            
    def get_etherscan_data(self, address: str) -> dict:
        """Get additional data from Etherscan API"""
        try:
            api_key = self.options["ETHERSCAN_API_KEY"]["value"]
            if not api_key:
                return {"note": "No Etherscan API key provided"}
                
            network = self.options["NETWORK"]["value"]
            
            # Map network to Etherscan URL
            urls = {
                "mainnet": "https://api.etherscan.io/api",
                "goerli": "https://api-goerli.etherscan.io/api",
                "sepolia": "https://api-sepolia.etherscan.io/api"
            }
            
            base_url = urls.get(network, urls["mainnet"])
            
            data = {
                "source_code": None,
                "contract_name": None,
                "compiler_version": None,
                "optimization": None,
                "transactions": []
            }
            
            # Get contract source code
            try:
                source_url = f"{base_url}?module=contract&action=getsourcecode&address={address}&apikey={api_key}"
                response = requests.get(source_url, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    if result["status"] == "1" and result["result"]:
                        source_data = result["result"][0]
                        data["source_code"] = len(source_data.get("SourceCode", "")) > 0
                        data["contract_name"] = source_data.get("ContractName", "Unknown")
                        data["compiler_version"] = source_data.get("CompilerVersion", "Unknown")
                        data["optimization"] = source_data.get("OptimizationUsed", "Unknown")
                        
            except Exception as e:
                logger.warning(f"Failed to get source code: {e}")
                
            # Get recent transactions
            try:
                tx_url = f"{base_url}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc&apikey={api_key}"
                response = requests.get(tx_url, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    if result["status"] == "1":
                        data["transactions"] = len(result["result"])
                        
            except Exception as e:
                logger.warning(f"Failed to get transactions: {e}")
                
            return data
            
        except Exception as e:
            logger.error(f"Etherscan API error: {e}")
            return {"error": str(e)}
            
    def detect_contract_type(self, bytecode_analysis: dict, etherscan_data: dict) -> str:
        """Detect the type of contract based on analysis"""
        try:
            # Check for ERC20 patterns
            erc20_functions = ["balanceOf", "transfer", "totalSupply"]
            detected_functions = [f["description"] for f in bytecode_analysis.get("functions_detected", [])]
            
            if any(func in str(detected_functions) for func in erc20_functions):
                return "ERC20 Token"
                
            # Check for ownership patterns
            if any("owner" in func.lower() for func in str(detected_functions)):
                return "Ownable Contract"
                
            # Check for proxy patterns
            if any("delegatecall" in pattern["pattern"] for pattern in bytecode_analysis.get("security_patterns", [])):
                return "Proxy Contract"
                
            # Check contract name from Etherscan
            name = etherscan_data.get("contract_name", "").lower()
            if "token" in name:
                return "Token Contract"
            elif "exchange" in name or "swap" in name:
                return "DeFi Exchange"
            elif "pool" in name or "vault" in name:
                return "DeFi Pool/Vault"
                
            return "Generic Smart Contract"
            
        except Exception as e:
            logger.error(f"Contract type detection failed: {e}")
            return "Unknown"
            
    def generate_security_assessment(self, analysis_data: dict) -> dict:
        """Generate security assessment based on analysis"""
        try:
            assessment = {
                "risk_level": "low",
                "vulnerabilities": [],
                "recommendations": [],
                "security_score": 85
            }
            
            bytecode = analysis_data.get("bytecode_analysis", {})
            
            # Check for high-risk patterns
            high_risk_patterns = ["delegatecall", "selfdestruct", "suicide"]
            medium_risk_patterns = ["call", "sstore"]
            
            risk_score = 0
            
            for pattern in bytecode.get("security_patterns", []):
                pattern_name = pattern.get("pattern", "")
                
                if pattern_name in high_risk_patterns:
                    assessment["vulnerabilities"].append(f"High risk: {pattern['description']}")
                    risk_score += 30
                elif pattern_name in medium_risk_patterns:
                    assessment["vulnerabilities"].append(f"Medium risk: {pattern['description']}")
                    risk_score += 15
                    
            # Adjust risk level based on score
            if risk_score >= 50:
                assessment["risk_level"] = "high"
                assessment["security_score"] = max(20, 85 - risk_score)
            elif risk_score >= 25:
                assessment["risk_level"] = "medium"
                assessment["security_score"] = max(40, 85 - risk_score)
            else:
                assessment["security_score"] = max(60, 85 - risk_score)
                
            # Generate recommendations
            if "delegatecall" in str(bytecode.get("security_patterns", [])):
                assessment["recommendations"].append("Review delegatecall usage for security implications")
                
            if "selfdestruct" in str(bytecode.get("security_patterns", [])):
                assessment["recommendations"].append("Verify selfdestruct access controls")
                
            if len(bytecode.get("functions_detected", [])) < 3:
                assessment["recommendations"].append("Limited functionality detected - verify contract completeness")
                
            return assessment
            
        except Exception as e:
            logger.error(f"Security assessment failed: {e}")
            return {"error": str(e)}
            
    def save_results_to_file(self, results: dict) -> str:
        """Save results to file"""
        try:
            output_format = self.options["OUTPUT_FORMAT"]["value"]
            address = self.options["TARGET_CONTRACT"]["value"]
            filename = f"contract_info_{address[:10]}_{output_format}"
            
            if output_format == "json":
                filename += ".json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            elif output_format == "csv":
                filename += ".csv"
                # Simple CSV output for key data
                with open(filename, 'w') as f:
                    f.write("Property,Value\n")
                    basic_info = results.get("basic_info", {})
                    for key, value in basic_info.items():
                        f.write(f"{key},{value}\n")
            else:  # txt format
                filename += ".txt"
                with open(filename, 'w') as f:
                    f.write(f"Contract Information Report\n")
                    f.write(f"=" * 40 + "\n\n")
                    f.write(json.dumps(results, indent=2, default=str))
                    
            logger.info(f"Results saved to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return ""
            
    def run(self) -> dict:
        """Main execution method"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Starting contract information gathering...")
        
        try:
            w3 = get_web3_connection(self.options["RPC_URL"]["value"])
            address = self.options["TARGET_CONTRACT"]["value"]
            
            results = {
                "scan_timestamp": None,
                "target_address": address,
                "basic_info": {},
                "bytecode_analysis": {},
                "etherscan_data": {},
                "contract_type": "",
                "security_assessment": {},
                "recommendations": []
            }
            
            from datetime import datetime
            results["scan_timestamp"] = datetime.now().isoformat()
            
            # Get basic contract information
            logger.info("Gathering basic contract information...")
            results["basic_info"] = self.get_basic_contract_info(w3, address)
            
            if results["basic_info"].get("is_contract"):
                # Analyze bytecode
                logger.info("Analyzing contract bytecode...")
                results["bytecode_analysis"] = self.analyze_bytecode(w3, address)
                
                # Get Etherscan data
                logger.info("Fetching Etherscan data...")
                results["etherscan_data"] = self.get_etherscan_data(address)
                
                # Detect contract type
                logger.info("Detecting contract type...")
                results["contract_type"] = self.detect_contract_type(
                    results["bytecode_analysis"], 
                    results["etherscan_data"]
                )
                
                # Generate security assessment
                logger.info("Generating security assessment...")
                results["security_assessment"] = self.generate_security_assessment(results)
                
                # Generate general recommendations
                results["recommendations"] = [
                    "Review contract source code if available",
                    "Verify contract ownership and access controls",
                    "Check for recent security audits",
                    "Monitor contract activity and transactions"
                ]
                
                if self.options["DEEP_ANALYSIS"]["value"].lower() == "true":
                    logger.info("Performing deep analysis...")
                    # Add more detailed analysis here
                    results["deep_analysis"] = {
                        "note": "Deep analysis feature placeholder",
                        "advanced_patterns": "Not implemented in demo"
                    }
                    
            else:
                results["contract_type"] = "Externally Owned Account (EOA)"
                results["recommendations"] = [
                    "This is an EOA, not a smart contract",
                    "Check transaction history for activity patterns"
                ]
                
            # Save results if requested
            if self.options["SAVE_RESULTS"]["value"].lower() == "true":
                filename = self.save_results_to_file(results)
                results["output_file"] = filename
                
            logger.info("Contract information gathering completed successfully")
            return {
                "result": "success",
                "message": f"Contract analysis completed for {address}",
                "data": results
            }
            
        except Exception as e:
            logger.error(f"Contract info scan failed: {e}")
            return {
                "result": "error", 
                "message": f"Scan failed: {str(e)}"
            }