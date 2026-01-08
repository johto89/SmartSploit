"""
Base Module Classes for SmartSploit Framework
Provides common structure and interface for all module types
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class ModuleType(Enum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary" 
    PAYLOAD = "payload"
    POST = "post"

class ExecutionResult:
    """Standard result object for module executions"""
    def __init__(self, success: bool = False, message: str = "", data: Optional[Dict] = None):
        self.success = success
        self.message = message
        self.data = data if data is not None else {}
        self.timestamp = None
        
    def __str__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"[{status}] {self.message}"

class BaseModule(ABC):
    """Base class for all SmartSploit modules"""
    
    def __init__(self):
        self.name = ""
        self.description = ""
        self.author = ""
        self.version = "1.0"
        self.module_type = None
        self.targets = []
        self.references = []
        self.options = {}
        self.required_options = []
        self.framework = None
        
    @abstractmethod
    def info(self) -> Dict[str, Any]:
        """Return module information"""
        return {
            'name': self.name,
            'description': self.description,
            'author': self.author,
            'version': self.version,
            'type': self.module_type.value if self.module_type else 'unknown',
            'targets': self.targets,
            'references': self.references,
            'options': self.options,
            'required_options': self.required_options
        }
    
    @abstractmethod
    def check(self) -> bool:
        """Check if module can run with current options"""
        for option in self.required_options:
            if option not in self.options or not self.options[option]:
                logger.error(f"Required option '{option}' not set")
                return False
        return True
    
    @abstractmethod
    def run(self) -> ExecutionResult:
        """Execute the module"""
        pass
    
    def set_option(self, key: str, value: Any):
        """Set module option"""
        self.options[key] = value
        
    def get_option(self, key: str, default=None):
        """Get module option value"""
        return self.options.get(key, default)
        
    def set_framework(self, framework):
        """Set framework reference"""
        self.framework = framework

class ExploitModule(BaseModule):
    """Base class for exploit modules"""
    
    def __init__(self):
        super().__init__()
        self.module_type = ModuleType.EXPLOIT
        self.rank = "normal"  # low, normal, high, excellent
        self.payload_type = "generic"
        
    def exploit(self) -> ExecutionResult:
        """Main exploit function - override in subclasses"""
        return self.run()

class AuxiliaryModule(BaseModule):
    """Base class for auxiliary modules"""
    
    def __init__(self):
        super().__init__()
        self.module_type = ModuleType.AUXILIARY
        self.scan_type = "info"  # info, scan, gather
        
    def auxiliary_run(self) -> ExecutionResult:
        """Main auxiliary function - override in subclasses"""
        return self.run()

class PayloadModule(BaseModule):
    """Base class for payload modules"""
    
    def __init__(self):
        super().__init__()
        self.module_type = ModuleType.PAYLOAD
        self.payload_size = 0
        self.payload_type = "generic"
        
    def generate(self) -> str:
        """Generate payload code - override in subclasses"""
        return ""
    
    def run(self) -> ExecutionResult:
        """Execute payload generation"""
        try:
            payload = self.generate()
            return ExecutionResult(True, "Payload generated successfully", {"payload": payload})
        except Exception as e:
            return ExecutionResult(False, f"Payload generation failed: {str(e)}")

class PostModule(BaseModule):
    """Base class for post-exploitation modules"""
    
    def __init__(self):
        super().__init__()
        self.module_type = ModuleType.POST
        self.session_type = "generic"
        
    def post_exploit(self) -> ExecutionResult:
        """Main post-exploitation function - override in subclasses"""
        return self.run()