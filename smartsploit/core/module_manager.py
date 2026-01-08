"""
Module Manager - Handles loading and execution of modules
"""

import os
import sys
import importlib
import logging
from typing import Dict, List, Optional
from smartsploit.lib.base_module import BaseModule, ModuleType

logger = logging.getLogger(__name__)

class ModuleManager:
    """Manages loading and execution of modules"""
    
    def __init__(self, framework):
        self.framework = framework
        self.modules: Dict[str, any] = {}
        self.module_paths: Dict[ModuleType, str] = {
            ModuleType.EXPLOIT: "smartsploit/modules/exploits",
            ModuleType.AUXILIARY: "smartsploit/modules/auxiliary", 
            ModuleType.PAYLOAD: "smartsploit/modules/payloads",
            ModuleType.POST: "smartsploit/modules/post"
        }
        
    def load_modules(self) -> None:
        """Load all modules from filesystem"""
        # Load actual modules from filesystem
        self._load_filesystem_modules()
        # Load hardcoded modules for demo
        self._load_demo_modules()
        
    def _load_filesystem_modules(self):
        """Load modules from filesystem"""
        try:
            # Load demo modules we created
            demo_modules = [
                ("exploits/reentrancy/demo_reentrancy", "smartsploit.modules.exploits.reentrancy.demo_reentrancy"),
                ("auxiliary/scanner/demo_scanner", "smartsploit.modules.auxiliary.scanner.demo_scanner"),
                ("payloads/generic/demo_payload", "smartsploit.modules.payloads.generic.demo_payload"),
                ("post/exfiltration/demo_exfiltration", "smartsploit.modules.post.exfiltration.demo_exfiltration")
            ]
            
            for module_name, module_path in demo_modules:
                try:
                    # Import module
                    module = importlib.import_module(module_path)
                    if hasattr(module, 'get_module'):
                        # Get module instance
                        module_instance = module.get_module()
                        # Set framework reference
                        module_instance.set_framework(self.framework)
                        # Register module
                        self.modules[module_name] = module_instance
                        logger.debug(f"Loaded module: {module_name}")
                except Exception as e:
                    logger.warning(f"Failed to load module {module_name}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error loading filesystem modules: {str(e)}")
        
    def _load_demo_modules(self):
        """Load demo modules"""
        # Demo exploit modules
        self.modules["exploit/reentrancy/classic"] = type('ClassicReentrancy', (), {
            'info': type('info', (), {
                'name': 'Classic Reentrancy Attack',
                'description': 'Exploits classic reentrancy vulnerability in withdraw functions',
                'author': 'SmartSploit Team',
                'severity': 'high',
                'references': ['SWC-107'],
                'targets': ['contracts with vulnerable withdraw functions']
            })(),
            'options': {'TARGET': None, 'NETWORK': 'mainnet', 'AMOUNT': '1'},
            'required_options': ['TARGET'],
            'run': lambda **kwargs: {'result': 'success', 'message': 'Demo exploit executed'}
        })()
        
        self.modules["exploit/overflow/integer"] = type('IntegerOverflow', (), {
            'info': type('info', (), {
                'name': 'Integer Overflow Attack',
                'description': 'Exploits integer overflow vulnerabilities',
                'author': 'SmartSploit Team',
                'severity': 'medium',
                'references': ['SWC-101'],
                'targets': ['contracts with unsafe math operations']
            })(),
            'options': {'TARGET': None, 'NETWORK': 'mainnet'},
            'required_options': ['TARGET'],
            'run': lambda **kwargs: {'result': 'success', 'message': 'Demo exploit executed'}
        })()
        
        self.modules["exploit/access_control/tx_origin"] = type('TxOriginAttack', (), {
            'info': type('info', (), {
                'name': 'tx.origin Authentication Attack',
                'description': 'Exploits tx.origin authentication vulnerability',
                'author': 'SmartSploit Team',
                'severity': 'medium',
                'references': ['SWC-115'],
                'targets': ['contracts using tx.origin for authentication']
            })(),
            'options': {'TARGET': None, 'NETWORK': 'mainnet'},
            'required_options': ['TARGET'],
            'run': lambda **kwargs: {'result': 'success', 'message': 'Demo exploit executed'}
        })()
        
        # Demo auxiliary modules
        self.modules["auxiliary/scanner/vulnerability"] = type('VulnerabilityScanner', (), {
            'info': type('info', (), {
                'name': 'Vulnerability Scanner',
                'description': 'Scans smart contracts for known vulnerabilities',
                'author': 'SmartSploit Team',
                'severity': 'info',
                'references': [],
                'targets': ['any smart contract']
            })(),
            'options': {'TARGET': None, 'NETWORK': 'mainnet'},
            'required_options': ['TARGET'],
            'run': lambda **kwargs: {'result': 'success', 'data': {'vulnerabilities': ['reentrancy', 'overflow']}}
        })()
        
        logger.info(f"Loaded {len(self.modules)} total modules")
            
    def reload_modules(self):
        """Reload all modules"""
        self.modules.clear()
        self.load_modules()
        
    def get_module(self, module_path: str) -> Optional[any]:
        """Get module by path"""
        return self.modules.get(module_path)
        
    def list_modules(self, module_type: Optional[str] = None) -> List[str]:
        """List available modules"""
        if module_type:
            return [name for name in self.modules.keys() if name.startswith(module_type)]
        return list(self.modules.keys())
        
    def search_modules(self, query: str) -> List[str]:
        """Search modules by name or description"""
        results = []
        query_lower = query.lower()
        
        for name, module in self.modules.items():
            # Search in module name
            if query_lower in name.lower():
                results.append(name)
                continue
                
            # Search in module info if available
            try:
                if hasattr(module, 'info'):
                    info = module.info() if callable(module.info) else module.info
                    if isinstance(info, dict):
                        desc = info.get('description', '').lower()
                        if query_lower in desc:
                            results.append(name)
                    elif hasattr(info, 'description'):
                        if query_lower in info.description.lower():
                            results.append(name)
            except:
                pass
                
        return results
        
    def get_module_info(self, module_path: str) -> Optional[Dict]:
        """Get detailed module information"""
        module = self.get_module(module_path)
        if not module:
            return None
            
        try:
            if hasattr(module, 'info'):
                info = module.info() if callable(module.info) else module.info
                if isinstance(info, dict):
                    return info
                elif hasattr(info, '__dict__'):
                    return info.__dict__
            return {"name": module_path, "description": "No description available"}
        except:
            return {"name": module_path, "description": "Error getting module info"}
