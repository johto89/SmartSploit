"""
GitHub Intelligence Gathering Module
SmartSploit Framework - Crawls GitHub for smart contract repositories and vulnerability patterns
"""

from smartsploit.lib.base_module import BaseAuxiliary, ModuleInfo
import requests
import json
import base64
import time
import re
import logging

logger = logging.getLogger(__name__)

class GitHubCrawler(BaseAuxiliary):
    """Gathers intelligence from GitHub repositories containing smart contracts"""
    
    def __init__(self):
        super().__init__()
        self.name = "GitHub Intelligence Crawler"
        self.description = "Crawls GitHub for smart contract source code and vulnerability patterns"
        self.author = "SmartSploit Team"
        
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "https://docs.github.com/en/rest",
                "Smart Contract Security Analysis",
                "Code Repository Intelligence"
            ],
            severity="info",
            targets=["Smart contract repositories", "DeFi projects", "Security vulnerabilities", "Code patterns"]
        )
        
        self.options = {
            "SEARCH_QUERY": {"value": "solidity vulnerability", "required": True, "description": "GitHub search query"},
            "GITHUB_TOKEN": {"value": "", "required": False, "description": "GitHub API token for higher rate limits"},
            "MAX_REPOSITORIES": {"value": "20", "required": False, "description": "Maximum repositories to analyze"},
            "INCLUDE_FORKS": {"value": "false", "required": False, "description": "Include forked repositories"},
            "MIN_STARS": {"value": "10", "required": False, "description": "Minimum stars for repository"},
            "LANGUAGE_FILTER": {"value": "solidity", "required": False, "description": "Programming language filter"},
            "VULNERABILITY_PATTERNS": {"value": "true", "required": False, "description": "Search for vulnerability patterns"},
            "DOWNLOAD_SOURCE": {"value": "false", "required": False, "description": "Download source code for analysis"},
            "OUTPUT_FORMAT": {"value": "json", "required": False, "description": "Output format (json, csv)"},
            "SAVE_RESULTS": {"value": "true", "required": False, "description": "Save results to file"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        if not self.options["SEARCH_QUERY"]["value"]:
            logger.error("Search query is required")
            return False
        return True
        
    def get_github_headers(self) -> dict:
        """Get GitHub API headers with authentication if token provided"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SmartSploit-Framework"
        }
        
        token = self.options["GITHUB_TOKEN"]["value"]
        if token:
            headers["Authorization"] = f"token {token}"
            
        return headers
        
    def search_repositories(self) -> list:
        """Search GitHub repositories based on query"""
        try:
            query = self.options["SEARCH_QUERY"]["value"]
            max_repos = int(self.options["MAX_REPOSITORIES"]["value"])
            min_stars = int(self.options["MIN_STARS"]["value"])
            language = self.options["LANGUAGE_FILTER"]["value"]
            include_forks = self.options["INCLUDE_FORKS"]["value"].lower() == "true"
            
            # Build search query
            search_params = [f"language:{language}"] if language else []
            search_params.append(f"stars:>={min_stars}")
            
            if not include_forks:
                search_params.append("fork:false")
                
            full_query = f"{query} {' '.join(search_params)}"
            
            headers = self.get_github_headers()
            
            repositories = []
            page = 1
            per_page = min(100, max_repos)
            
            while len(repositories) < max_repos:
                params = {
                    "q": full_query,
                    "sort": "stars",
                    "order": "desc",
                    "page": page,
                    "per_page": per_page
                }
                
                response = requests.get(
                    "https://api.github.com/search/repositories",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    repos = data.get("items", [])
                    
                    if not repos:
                        break
                        
                    repositories.extend(repos)
                    
                    if len(repos) < per_page:
                        break
                        
                    page += 1
                    time.sleep(1)  # Rate limiting
                    
                elif response.status_code == 403:
                    logger.warning("GitHub API rate limit exceeded")
                    break
                else:
                    logger.error(f"GitHub API error: {response.status_code}")
                    break
                    
            logger.info(f"Found {len(repositories)} repositories")
            return repositories[:max_repos]
            
        except Exception as e:
            logger.error(f"Repository search failed: {e}")
            return []
            
    def analyze_repository(self, repo: dict) -> dict:
        """Analyze a single repository for security information"""
        try:
            repo_info = {
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "description": repo.get("description"),
                "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"),
                "language": repo.get("language"),
                "created_at": repo.get("created_at"),
                "updated_at": repo.get("updated_at"),
                "clone_url": repo.get("clone_url"),
                "security_analysis": {},
                "files_analyzed": [],
                "vulnerabilities_found": []
            }
            
            # Get repository contents
            contents = self.get_repository_contents(repo["full_name"])
            repo_info["security_analysis"] = self.analyze_repository_security(repo["full_name"], contents)
            
            return repo_info
            
        except Exception as e:
            logger.error(f"Repository analysis failed for {repo.get('name', 'unknown')}: {e}")
            return {"error": str(e)}
            
    def get_repository_contents(self, repo_full_name: str) -> list:
        """Get repository file contents recursively"""
        try:
            headers = self.get_github_headers()
            contents = []
            
            # Get root directory contents
            response = requests.get(
                f"https://api.github.com/repos/{repo_full_name}/contents",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                items = response.json()
                
                for item in items:
                    if item["type"] == "file" and item["name"].endswith((".sol", ".vy", ".py", ".js", ".md")):
                        # Get file content for analysis
                        file_content = self.get_file_content(repo_full_name, item["path"])
                        if file_content:
                            contents.append({
                                "path": item["path"],
                                "name": item["name"],
                                "size": item["size"],
                                "content": file_content
                            })
                    elif item["type"] == "dir" and item["name"] in ["contracts", "src", "lib", "test"]:
                        # Recursively get contents of important directories
                        dir_contents = self.get_directory_contents(repo_full_name, item["path"])
                        contents.extend(dir_contents)
                        
                time.sleep(0.5)  # Rate limiting
                
            return contents
            
        except Exception as e:
            logger.error(f"Failed to get repository contents: {e}")
            return []
            
    def get_directory_contents(self, repo_full_name: str, path: str) -> list:
        """Get contents of a specific directory"""
        try:
            headers = self.get_github_headers()
            contents = []
            
            response = requests.get(
                f"https://api.github.com/repos/{repo_full_name}/contents/{path}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                items = response.json()
                
                for item in items:
                    if item["type"] == "file" and item["name"].endswith((".sol", ".vy")):
                        file_content = self.get_file_content(repo_full_name, item["path"])
                        if file_content:
                            contents.append({
                                "path": item["path"],
                                "name": item["name"],
                                "size": item["size"],
                                "content": file_content
                            })
                            
                time.sleep(0.3)  # Rate limiting
                
            return contents
            
        except Exception as e:
            logger.error(f"Failed to get directory contents: {e}")
            return []
            
    def get_file_content(self, repo_full_name: str, file_path: str) -> str:
        """Get content of a specific file"""
        try:
            headers = self.get_github_headers()
            
            response = requests.get(
                f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                file_data = response.json()
                
                if file_data.get("encoding") == "base64":
                    content = base64.b64decode(file_data["content"]).decode('utf-8', errors='ignore')
                    return content
                    
            return ""
            
        except Exception as e:
            logger.debug(f"Failed to get file content for {file_path}: {e}")
            return ""
            
    def analyze_repository_security(self, repo_full_name: str, contents: list) -> dict:
        """Analyze repository for security vulnerabilities"""
        try:
            security_analysis = {
                "total_files": len(contents),
                "solidity_files": 0,
                "vulnerability_patterns": [],
                "security_features": [],
                "external_dependencies": [],
                "test_coverage": {"has_tests": False, "test_files": []},
                "documentation": {"has_readme": False, "has_security_doc": False},
                "overall_risk": "low"
            }
            
            vulnerability_patterns = {
                "reentrancy": [
                    r"\.call\s*\(",
                    r"\.delegatecall\s*\(",
                    r"external.*payable",
                    r"function.*external.*{[^}]*\.call"
                ],
                "overflow": [
                    r"[+\-*/]\s*=",
                    r"SafeMath",
                    r"pragma\s+solidity\s+\^?0\.[4-7]"
                ],
                "access_control": [
                    r"tx\.origin",
                    r"msg\.sender\s*==",
                    r"onlyOwner",
                    r"require\s*\(\s*msg\.sender"
                ],
                "randomness": [
                    r"block\.timestamp",
                    r"block\.number",
                    r"blockhash",
                    r"now\s*%"
                ],
                "dos": [
                    r"for\s*\([^)]*\.length",
                    r"while\s*\(",
                    r"unbounded.*loop"
                ]
            }
            
            security_features = [
                r"require\s*\(",
                r"assert\s*\(",
                r"modifier\s+\w+",
                r"OpenZeppelin",
                r"ReentrancyGuard",
                r"Pausable",
                r"AccessControl"
            ]
            
            risk_score = 0
            
            for file_info in contents:
                content = file_info["content"]
                file_path = file_info["path"]
                
                if file_path.endswith(".sol"):
                    security_analysis["solidity_files"] += 1
                    
                    # Check for vulnerability patterns
                    for vuln_type, patterns in vulnerability_patterns.items():
                        for pattern in patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                            if matches:
                                security_analysis["vulnerability_patterns"].append({
                                    "type": vuln_type,
                                    "pattern": pattern,
                                    "file": file_path,
                                    "matches": len(matches),
                                    "severity": self._get_vulnerability_severity(vuln_type)
                                })
                                risk_score += len(matches) * self._get_risk_multiplier(vuln_type)
                                
                    # Check for security features
                    for feature_pattern in security_features:
                        matches = re.findall(feature_pattern, content, re.IGNORECASE)
                        if matches:
                            security_analysis["security_features"].append({
                                "pattern": feature_pattern,
                                "file": file_path,
                                "matches": len(matches)
                            })
                            risk_score -= len(matches) * 2  # Security features reduce risk
                            
                    # Check for external dependencies
                    import_patterns = [
                        r"import\s+[\"']([^\"']+)[\"']",
                        r"from\s+[\"']([^\"']+)[\"']"
                    ]
                    
                    for pattern in import_patterns:
                        imports = re.findall(pattern, content)
                        for imp in imports:
                            if imp not in security_analysis["external_dependencies"]:
                                security_analysis["external_dependencies"].append(imp)
                                
                elif file_path.lower().endswith((".test.sol", ".spec.sol")) or "test" in file_path.lower():
                    security_analysis["test_coverage"]["has_tests"] = True
                    security_analysis["test_coverage"]["test_files"].append(file_path)
                    
                elif file_path.lower() == "readme.md":
                    security_analysis["documentation"]["has_readme"] = True
                    if any(keyword in content.lower() for keyword in ["security", "audit", "vulnerability"]):
                        security_analysis["documentation"]["has_security_doc"] = True
                        
            # Calculate overall risk
            if risk_score > 20:
                security_analysis["overall_risk"] = "high"
            elif risk_score > 10:
                security_analysis["overall_risk"] = "medium"
            else:
                security_analysis["overall_risk"] = "low"
                
            security_analysis["risk_score"] = max(0, risk_score)
            
            return security_analysis
            
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            return {"error": str(e)}
            
    def _get_vulnerability_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        severity_map = {
            "reentrancy": "high",
            "overflow": "high",
            "access_control": "medium", 
            "randomness": "medium",
            "dos": "low"
        }
        return severity_map.get(vuln_type, "medium")
        
    def _get_risk_multiplier(self, vuln_type: str) -> int:
        """Get risk score multiplier for vulnerability type"""
        multipliers = {
            "reentrancy": 5,
            "overflow": 4,
            "access_control": 3,
            "randomness": 2,
            "dos": 1
        }
        return multipliers.get(vuln_type, 2)
        
    def generate_security_report(self, repositories: list) -> dict:
        """Generate comprehensive security report"""
        try:
            report = {
                "summary": {
                    "total_repositories": len(repositories),
                    "high_risk_repos": 0,
                    "medium_risk_repos": 0,
                    "low_risk_repos": 0,
                    "total_vulnerabilities": 0
                },
                "vulnerability_statistics": {},
                "top_vulnerable_repos": [],
                "security_recommendations": []
            }
            
            vulnerability_counts = {}
            
            for repo in repositories:
                if "error" in repo:
                    continue
                    
                risk_level = repo.get("security_analysis", {}).get("overall_risk", "low")
                report["summary"][f"{risk_level}_risk_repos"] += 1
                
                # Count vulnerabilities by type
                vulns = repo.get("security_analysis", {}).get("vulnerability_patterns", [])
                report["summary"]["total_vulnerabilities"] += len(vulns)
                
                for vuln in vulns:
                    vuln_type = vuln["type"]
                    vulnerability_counts[vuln_type] = vulnerability_counts.get(vuln_type, 0) + 1
                    
                # Track high-risk repositories
                risk_score = repo.get("security_analysis", {}).get("risk_score", 0)
                if risk_score > 15:
                    report["top_vulnerable_repos"].append({
                        "name": repo["name"],
                        "full_name": repo["full_name"],
                        "risk_score": risk_score,
                        "stars": repo["stars"],
                        "vulnerabilities": len(vulns)
                    })
                    
            report["vulnerability_statistics"] = vulnerability_counts
            
            # Sort top vulnerable repos by risk score
            report["top_vulnerable_repos"].sort(key=lambda x: x["risk_score"], reverse=True)
            report["top_vulnerable_repos"] = report["top_vulnerable_repos"][:10]
            
            # Generate recommendations
            if vulnerability_counts.get("reentrancy", 0) > 0:
                report["security_recommendations"].append("Implement reentrancy guards in contracts")
            if vulnerability_counts.get("overflow", 0) > 0:
                report["security_recommendations"].append("Use SafeMath library or Solidity 0.8+")
            if vulnerability_counts.get("access_control", 0) > 0:
                report["security_recommendations"].append("Review access control mechanisms")
                
            return report
            
        except Exception as e:
            logger.error(f"Security report generation failed: {e}")
            return {"error": str(e)}
            
    def save_results_to_file(self, results: dict) -> str:
        """Save crawl results to file"""
        try:
            output_format = self.options["OUTPUT_FORMAT"]["value"]
            query = self.options["SEARCH_QUERY"]["value"].replace(" ", "_")
            filename = f"github_crawl_{query}_{int(time.time())}"
            
            if output_format == "json":
                filename += ".json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            else:  # csv
                filename += ".csv"
                with open(filename, 'w') as f:
                    f.write("Repository,Stars,Risk Level,Vulnerabilities,Description\n")
                    
                    for repo in results.get("repositories", []):
                        if "error" not in repo:
                            vulns = len(repo.get("security_analysis", {}).get("vulnerability_patterns", []))
                            risk = repo.get("security_analysis", {}).get("overall_risk", "unknown")
                            desc = repo.get("description", "").replace(",", ";")
                            
                            f.write(f"{repo['name']},{repo['stars']},{risk},{vulns},{desc}\n")
                            
            logger.info(f"Results saved to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return ""
            
    def run(self) -> dict:
        """Main execution method"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Starting GitHub intelligence gathering...")
        
        try:
            # Search for repositories
            repositories = self.search_repositories()
            
            if not repositories:
                return {"result": "error", "message": "No repositories found matching search criteria"}
                
            # Analyze each repository
            analyzed_repos = []
            
            for i, repo in enumerate(repositories):
                logger.info(f"Analyzing repository {i+1}/{len(repositories)}: {repo['name']}")
                
                if self.options["VULNERABILITY_PATTERNS"]["value"].lower() == "true":
                    analysis = self.analyze_repository(repo)
                    analyzed_repos.append(analysis)
                else:
                    # Basic info only
                    analyzed_repos.append({
                        "name": repo.get("name"),
                        "full_name": repo.get("full_name"),
                        "description": repo.get("description"),
                        "stars": repo.get("stargazers_count"),
                        "language": repo.get("language"),
                        "clone_url": repo.get("clone_url")
                    })
                    
                time.sleep(1)  # Rate limiting
                
            # Generate security report
            security_report = self.generate_security_report(analyzed_repos)
            
            results = {
                "search_query": self.options["SEARCH_QUERY"]["value"],
                "total_repositories": len(analyzed_repos),
                "repositories": analyzed_repos,
                "security_report": security_report,
                "crawl_timestamp": int(time.time())
            }
            
            # Save results if requested
            if self.options["SAVE_RESULTS"]["value"].lower() == "true":
                filename = self.save_results_to_file(results)
                results["output_file"] = filename
                
            logger.info("GitHub intelligence gathering completed")
            
            return {
                "result": "success",
                "message": f"Analyzed {len(analyzed_repos)} repositories",
                "data": results
            }
            
        except Exception as e:
            logger.error(f"GitHub crawler failed: {e}")
            return {"result": "error", "message": str(e)}