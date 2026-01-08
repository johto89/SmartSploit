"""
Contract Analyzer - Static analysis tools for smart contracts
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class ContractAnalyzer:
    """Static analysis tools for smart contract security"""
    
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns"""
        return {
            'reentrancy': [
                r'\.call\{value:.*?\}\(',
                r'\.call\(',
                r'\.transfer\(',
                r'\.send\(',
            ],
            'integer_overflow': [
                r'\+(?!\+)',  # Addition without overflow check
                r'\*(?!\*)',  # Multiplication 
                r'-(?!-)',    # Subtraction
            ],
            'unchecked_external_calls': [
                r'\.call\([^)]*\);(?!\s*require)',
                r'\.delegatecall\([^)]*\);(?!\s*require)',
            ],
            'tx_origin': [
                r'tx\.origin',
            ],
            'timestamp_dependence': [
                r'block\.timestamp',
                r'now\s*[<>=]',
            ],
            'unsafe_delegatecall': [
                r'delegatecall\(',
            ]
        }
        
    def analyze_source_code(self, source_code: str) -> Dict[str, any]:
        """Analyze smart contract source code for vulnerabilities"""
        results = {
            'vulnerabilities': {},
            'severity': 'LOW',
            'recommendations': [],
            'functions': self._extract_functions(source_code),
            'modifiers': self._extract_modifiers(source_code),
            'events': self._extract_events(source_code)
        }
        
        # Check for vulnerability patterns
        for vuln_type, patterns in self.vulnerability_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.finditer(pattern, source_code, re.IGNORECASE)
                for match in found:
                    line_num = source_code[:match.start()].count('\n') + 1
                    matches.append({
                        'line': line_num,
                        'code': match.group(),
                        'pattern': pattern
                    })
            
            if matches:
                results['vulnerabilities'][vuln_type] = matches
                
        # Determine overall severity
        if results['vulnerabilities']:
            critical_vulns = ['reentrancy', 'unchecked_external_calls', 'unsafe_delegatecall']
            if any(vuln in results['vulnerabilities'] for vuln in critical_vulns):
                results['severity'] = 'HIGH'
            elif len(results['vulnerabilities']) > 2:
                results['severity'] = 'MEDIUM'
                
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results['vulnerabilities'])
        
        return results
        
    def analyze_bytecode(self, bytecode: str) -> Dict[str, any]:
        """Analyze contract bytecode for patterns"""
        if not bytecode or bytecode == '0x':
            return {'error': 'No bytecode provided'}
            
        # Remove 0x prefix
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
            
        results = {
            'size': len(bytecode) // 2,
            'opcodes': self._extract_opcodes(bytecode),
            'patterns': self._detect_bytecode_patterns(bytecode),
            'functions': self._extract_function_signatures(bytecode)
        }
        
        return results
        
    def _extract_functions(self, source_code: str) -> List[Dict]:
        """Extract function definitions from source code"""
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|private|internal|external)?\s*(view|pure|payable)?\s*(?:returns\s*\([^)]*\))?\s*\{'
        functions = []
        
        for match in re.finditer(function_pattern, source_code, re.IGNORECASE):
            functions.append({
                'name': match.group(1),
                'visibility': match.group(2) or 'internal',
                'state_mutability': match.group(3) or '',
                'line': source_code[:match.start()].count('\n') + 1
            })
            
        return functions
        
    def _extract_modifiers(self, source_code: str) -> List[str]:
        """Extract modifier definitions"""
        modifier_pattern = r'modifier\s+(\w+)'
        return [match.group(1) for match in re.finditer(modifier_pattern, source_code, re.IGNORECASE)]
        
    def _extract_events(self, source_code: str) -> List[str]:
        """Extract event definitions"""
        event_pattern = r'event\s+(\w+)'
        return [match.group(1) for match in re.finditer(event_pattern, source_code, re.IGNORECASE)]
        
    def _extract_opcodes(self, bytecode: str) -> Dict[str, int]:
        """Extract and count opcodes from bytecode"""
        opcode_map = {
            '00': 'STOP', '01': 'ADD', '02': 'MUL', '03': 'SUB', '04': 'DIV',
            '05': 'SDIV', '06': 'MOD', '07': 'SMOD', '08': 'ADDMOD', '09': 'MULMOD',
            '0a': 'EXP', '0b': 'SIGNEXTEND', '10': 'LT', '11': 'GT', '12': 'SLT',
            '13': 'SGT', '14': 'EQ', '15': 'ISZERO', '16': 'AND', '17': 'OR',
            '18': 'XOR', '19': 'NOT', '1a': 'BYTE', '1b': 'SHL', '1c': 'SHR',
            '1d': 'SAR', '20': 'SHA3', '30': 'ADDRESS', '31': 'BALANCE',
            '32': 'ORIGIN', '33': 'CALLER', '34': 'CALLVALUE', '35': 'CALLDATALOAD',
            '36': 'CALLDATASIZE', '37': 'CALLDATACOPY', '38': 'CODESIZE',
            '39': 'CODECOPY', '3a': 'GASPRICE', '3b': 'EXTCODESIZE',
            '3c': 'EXTCODECOPY', '3d': 'RETURNDATASIZE', '3e': 'RETURNDATACOPY',
            '3f': 'EXTCODEHASH', '40': 'BLOCKHASH', '41': 'COINBASE',
            '42': 'TIMESTAMP', '43': 'NUMBER', '44': 'DIFFICULTY', '45': 'GASLIMIT',
            '50': 'POP', '51': 'MLOAD', '52': 'MSTORE', '53': 'MSTORE8',
            '54': 'SLOAD', '55': 'SSTORE', '56': 'JUMP', '57': 'JUMPI',
            '58': 'PC', '59': 'MSIZE', '5a': 'GAS', '5b': 'JUMPDEST',
            'f0': 'CREATE', 'f1': 'CALL', 'f2': 'CALLCODE', 'f3': 'RETURN',
            'f4': 'DELEGATECALL', 'f5': 'CREATE2', 'fa': 'STATICCALL',
            'fd': 'REVERT', 'fe': 'INVALID', 'ff': 'SELFDESTRUCT'
        }
        
        opcodes = {}
        for i in range(0, len(bytecode), 2):
            if i + 1 < len(bytecode):
                opcode_hex = bytecode[i:i+2].lower()
                opcode_name = opcode_map.get(opcode_hex, f'UNK_{opcode_hex}')
                opcodes[opcode_name] = opcodes.get(opcode_name, 0) + 1
                
        return opcodes
        
    def _detect_bytecode_patterns(self, bytecode: str) -> List[str]:
        """Detect vulnerability patterns in bytecode"""
        patterns = []
        
        # Reentrancy pattern: CALL followed by SLOAD
        if 'f1' in bytecode and '54' in bytecode:
            call_pos = bytecode.find('f1')
            sload_pos = bytecode.find('54', call_pos)
            if sload_pos != -1 and sload_pos - call_pos < 100:  # Within 50 bytes
                patterns.append('potential_reentrancy')
                
        # Delegatecall usage
        if 'f4' in bytecode:
            patterns.append('delegatecall_usage')
            
        # Multiple external calls
        call_count = bytecode.count('f1') + bytecode.count('fa')
        if call_count > 3:
            patterns.append('multiple_external_calls')
            
        # Timestamp dependency
        if '42' in bytecode:  # TIMESTAMP opcode
            patterns.append('timestamp_dependency')
            
        return patterns
        
    def _extract_function_signatures(self, bytecode: str) -> List[str]:
        """Extract function signatures from bytecode"""
        # Look for function selector patterns (first 4 bytes of function hash)
        signatures = []
        
        # Simple pattern: PUSH4 followed by 4-byte value (function selector)
        push4_pattern = '63'  # PUSH4 opcode
        i = 0
        while i < len(bytecode) - 10:
            if bytecode[i:i+2] == push4_pattern:
                selector = bytecode[i+2:i+10]
                signatures.append(f"0x{selector}")
                i += 10
            else:
                i += 2
                
        return signatures[:10]  # Return first 10 found
        
    def _generate_recommendations(self, vulnerabilities: Dict) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        if 'reentrancy' in vulnerabilities:
            recommendations.append("Use checks-effects-interactions pattern to prevent reentrancy")
            recommendations.append("Consider using OpenZeppelin's ReentrancyGuard")
            
        if 'integer_overflow' in vulnerabilities:
            recommendations.append("Use SafeMath library or Solidity 0.8+ automatic overflow checks")
            
        if 'unchecked_external_calls' in vulnerabilities:
            recommendations.append("Always check return values of external calls")
            recommendations.append("Use require() statements after external calls")
            
        if 'tx_origin' in vulnerabilities:
            recommendations.append("Use msg.sender instead of tx.origin for authentication")
            
        if 'timestamp_dependence' in vulnerabilities:
            recommendations.append("Avoid using block.timestamp for critical logic")
            recommendations.append("Use block numbers or external oracles for timing")
            
        if 'unsafe_delegatecall' in vulnerabilities:
            recommendations.append("Carefully validate delegatecall targets")
            recommendations.append("Consider using libraries instead of delegatecall")
            
        return recommendations
