"""
Smart Contract Exploitation Framework - Core Framework
Similar to Metasploit but specialized for smart contracts
"""

import os
import sys
import json
import logging
from typing import Dict, List, Optional, Any
from web3 import Web3
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModuleType(Enum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    PAYLOAD = "payload"
    POST = "post"

class ExploitResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"
    UNKNOWN = "unknown"

@dataclass
class Target:
    """Target smart contract information"""
    address: str
    network: str
    abi: Optional[List] = None
    source_code: Optional[str] = None
    compiler_version: Optional[str] = None
    balance: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExploitInfo:
    """Exploit module information"""
    name: str
    description: str
    author: str
    references: List[str] = field(default_factory=list)
    severity: str = "medium"
    targets: List[str] = field(default_factory=list)
    reliability: float = 0.5

class BaseModule(ABC):
    """Base class for all framework modules"""
    
    def __init__(self):
        self.info: ExploitInfo = None
        self.options: Dict[str, Any] = {}
        self.required_options: List[str] = []
        self.framework: 'SmartSploitFramework' = None
        
    @abstractmethod
    def run(self, **kwargs) -> Dict[str, Any]:
        """Main execution method"""
        pass
    
    def set_option(self, key: str, value: Any) -> None:
        """Set module option"""
        self.options[key] = value
        
    def get_option(self, key: str) -> Any:
        """Get module option"""
        return self.options.get(key)
        
    def validate_options(self) -> bool:
        """Validate required options are set"""
        for option in self.required_options:
            if option not in self.options or self.options[option] is None:
                logger.error(f"Required option '{option}' not set")
                return False
        return True

class BaseExploit(BaseModule):
    """Base class for exploit modules"""
    
    def __init__(self):
        super().__init__()
        self.target: Optional[Target] = None
        self.payloads: List[str] = []
        
    def check(self, target: Target) -> bool:
        """Check if target is vulnerable"""
        return False
        
    def exploit(self, target: Target) -> Dict[str, Any]:
        """Execute exploit against target"""
        return {"result": ExploitResult.UNKNOWN, "data": {}}
        
    def run(self, **kwargs) -> Dict[str, Any]:
        """Main execution wrapper"""
        if not self.validate_options():
            return {"result": ExploitResult.ERROR, "message": "Invalid options"}
            
        target_addr = self.get_option("TARGET")
        if not target_addr:
            return {"result": ExploitResult.ERROR, "message": "No target specified"}
            
        # Create target object
        target = Target(
            address=target_addr,
            network=self.get_option("NETWORK") or "mainnet"
        )
        
        # Check vulnerability
        if not self.check(target):
            return {"result": ExploitResult.FAILED, "message": "Target not vulnerable"}
            
        # Execute exploit
        return self.exploit(target)

class BaseAuxiliary(BaseModule):
    """Base class for auxiliary modules"""
    
    def scan(self, target: str) -> Dict[str, Any]:
        """Scan target for information"""
        return {}

class SmartSploitFramework:
    """Main framework class - similar to Metasploit's MSF"""
    
    def __init__(self):
        self.version = "2.1.0"
        self.current_module: Optional[BaseModule] = None
        self.global_options: Dict[str, Any] = {
            "LHOST": "127.0.0.1",
            "LPORT": 4444,
            "NETWORK": "mainnet",
            "VERBOSE": False
        }
        
        # Initialize components
        from .module_manager import ModuleManager
        from .session_manager import SessionManager
        from .blockchain_interface import BlockchainInterface
        
        self.module_manager = ModuleManager(self)
        self.session_manager = SessionManager()
        self.blockchain = BlockchainInterface()
        
    def initialize(self):
        """Initialize framework"""
        logger.info(f"SmartSploit Framework v{self.version}")
        logger.info("Loading modules...")
        self.module_manager.load_modules()
        logger.info("Framework initialized")
        
    def use_module(self, module_path: str) -> bool:
        """Load and use a specific module"""
        module = self.module_manager.get_module(module_path)
        if module:
            self.current_module = module
            self.current_module.framework = self
            logger.info(f"Using module: {module_path}")
            return True
        else:
            logger.error(f"Module not found: {module_path}")
            return False
            
    def show_info(self) -> Optional[Dict]:
        """Show current module information"""
        if not self.current_module:
            return None
            
        # Handle both callable and attribute access
        try:
            if hasattr(self.current_module, 'info'):
                info = self.current_module.info() if callable(self.current_module.info) else self.current_module.info
                if isinstance(info, dict):
                    return info
                elif hasattr(info, '__dict__'):
                    return info.__dict__
                else:
                    return {
                        "name": getattr(info, 'name', 'Unknown'),
                        "description": getattr(info, 'description', 'No description'),
                        "author": getattr(info, 'author', 'Unknown'),
                        "references": getattr(info, 'references', []),
                        "severity": getattr(info, 'severity', 'medium'),
                        "targets": getattr(info, 'targets', [])
                    }
        except:
            return {
                "name": getattr(self.current_module, 'name', 'Unknown'),
                "description": getattr(self.current_module, 'description', 'No description'),
                "author": getattr(self.current_module, 'author', 'Unknown'),
                "references": [],
                "severity": 'medium',
                "targets": []
            }
        
    def show_options(self) -> Dict[str, Any]:
        """Show current module options"""
        if not self.current_module:
            return self.global_options
            
        options = {}
        options.update(self.global_options)
        options.update(self.current_module.options)
        return options
        
    def set_option(self, key: str, value: Any) -> None:
        """Set option for current module or global"""
        if self.current_module:
            self.current_module.set_option(key, value)
        else:
            self.global_options[key] = value
            
    def run_current_module(self) -> Dict[str, Any]:
        """Execute current module"""
        if not self.current_module:
            return {"result": ExploitResult.ERROR, "message": "No module selected"}
            
        logger.info(f"Running module: {type(self.current_module).__name__}")
        return self.current_module.run()
        
    def search_modules(self, query: str) -> List[str]:
        """Search for modules by name or description"""
        all_modules = self.module_manager.list_modules()
        return [m for m in all_modules if query.lower() in m.lower()]

# Global framework instance
framework_instance = None

def get_framework() -> SmartSploitFramework:
    """Get global framework instance"""
    global framework_instance
    if framework_instance is None:
        framework_instance = SmartSploitFramework()
        framework_instance.initialize()
    return framework_instance
