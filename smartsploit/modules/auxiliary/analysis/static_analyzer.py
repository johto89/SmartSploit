import json
import re

class StaticAnalyzer:
    def __init__(self, code):
        self.code = code

    def parse_code(self):
        # Suppose we have a basic way to determine the language and tokenize
        tokens = []
        if "contract" in self.code:
            tokens = re.findall(r'[\w]+', self.code)
        return tokens

    def detect_vulnerabilities(self, tokens):
        vulnerabilities = []
        # Example pattern detections
        if 'tx.origin' in tokens:
            vulnerabilities.append('Usage of tx.origin detected.')
        if 'delegatecall' in tokens:
            vulnerabilities.append('Potential reentrancy via delegatecall detected.')
        # Add more patterns as needed
        return vulnerabilities

    def analyze(self):
        tokens = self.parse_code()
        vulnerabilities = self.detect_vulnerabilities(tokens)
        return vulnerabilities

    def output_findings(self, vulnerabilities):
        findings = {
            'vulnerabilities': vulnerabilities
        }
        return json.dumps(findings, indent=2)

# Example usage (not included in the module)
# code = "contract Sample { function unsafe(address addr) public { addr.delegatecall(abi.encodeWithSignature(\"f()\")); } }"
# analyzer = StaticAnalyzer(code)
# results = analyzer.analyze()
# print(analyzer.output_findings(results))