"""GitHub integration for code compliance scanning."""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import aiohttp
import base64

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GitHubRepository:
    """GitHub repository information."""
    
    owner: str
    name: str
    default_branch: str
    url: str
    private: bool


class GitHubConnector:
    """
    GitHub integration for compliance scanning.
    
    Features:
    - Repository scanning
    - Pull request analysis
    - Commit compliance checks
    - Security alerts retrieval
    - Automated PR comments
    - Branch protection verification
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize GitHub connector."""
        self.config = config or {}
        self.token = config.get('github_token') or os.getenv('GITHUB_TOKEN')
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    async def get_repository(self, owner: str, repo: str) -> GitHubRepository:
        """Get repository information."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to get repository: {response.status}")
                    
                    data = await response.json()
                    
                    return GitHubRepository(
                        owner=data['owner']['login'],
                        name=data['name'],
                        default_branch=data['default_branch'],
                        url=data['html_url'],
                        private=data['private']
                    )
        
        except Exception as e:
            logger.error(f"Failed to get repository {owner}/{repo}: {e}")
            raise
    
    async def scan_repository(self, owner: str, repo: str, branch: Optional[str] = None) -> Dict[str, Any]:
        """Scan entire repository for compliance issues."""
        try:
            # Get repository info
            repo_info = await self.get_repository(owner, repo)
            branch = branch or repo_info.default_branch
            
            logger.info(f"Scanning repository {owner}/{repo} on branch {branch}")
            
            # Get repository tree
            tree = await self._get_tree(owner, repo, branch)
            
            # Scan code files
            code_files = []
            for item in tree:
                if item['type'] == 'blob' and self._is_code_file(item['path']):
                    content = await self._get_file_content(owner, repo, item['path'], branch)
                    code_files.append({
                        'path': item['path'],
                        'content': content,
                        'size': item['size']
                    })
            
            # Get security alerts
            security_alerts = await self._get_security_alerts(owner, repo)
            
            # Check branch protection
            branch_protection = await self._check_branch_protection(owner, repo, branch)
            
            return {
                "repository": {
                    "owner": owner,
                    "name": repo,
                    "branch": branch,
                    "private": repo_info.private
                },
                "files_scanned": len(code_files),
                "code_files": code_files,
                "security_alerts": security_alerts,
                "branch_protection": branch_protection
            }
        
        except Exception as e:
            logger.error(f"Failed to scan repository: {e}")
            raise
    
    async def scan_pull_request(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        """Scan pull request for compliance issues."""
        try:
            logger.info(f"Scanning PR #{pr_number} in {owner}/{repo}")
            
            async with aiohttp.ClientSession() as session:
                # Get PR details
                pr_url = f"{self.api_base}/repos/{owner}/{repo}/pulls/{pr_number}"
                async with session.get(pr_url, headers=self.headers) as response:
                    pr_data = await response.json()
                
                # Get PR files
                files_url = f"{pr_url}/files"
                async with session.get(files_url, headers=self.headers) as response:
                    files_data = await response.json()
                
                # Analyze changed files
                changed_files = []
                for file in files_data:
                    if self._is_code_file(file['filename']):
                        changed_files.append({
                            'filename': file['filename'],
                            'status': file['status'],
                            'additions': file['additions'],
                            'deletions': file['deletions'],
                            'changes': file['changes'],
                            'patch': file.get('patch', '')
                        })
                
                return {
                    "pr_number": pr_number,
                    "title": pr_data['title'],
                    "author": pr_data['user']['login'],
                    "state": pr_data['state'],
                    "changed_files": changed_files,
                    "files_count": len(changed_files)
                }
        
        except Exception as e:
            logger.error(f"Failed to scan pull request: {e}")
            raise
    
    async def post_pr_comment(self, owner: str, repo: str, pr_number: int, comment: str) -> bool:
        """Post compliance comment on pull request."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}/issues/{pr_number}/comments"
                
                payload = {"body": comment}
                
                async with session.post(url, headers=self.headers, json=payload) as response:
                    if response.status == 201:
                        logger.info(f"Posted comment on PR #{pr_number}")
                        return True
                    else:
                        logger.error(f"Failed to post comment: {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Failed to post PR comment: {e}")
            return False
    
    async def create_issue(self, owner: str, repo: str, title: str, body: str, labels: Optional[List[str]] = None) -> Optional[int]:
        """Create compliance issue."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}/issues"
                
                payload = {
                    "title": title,
                    "body": body,
                    "labels": labels or ["compliance", "security"]
                }
                
                async with session.post(url, headers=self.headers, json=payload) as response:
                    if response.status == 201:
                        data = await response.json()
                        issue_number = data['number']
                        logger.info(f"Created issue #{issue_number}")
                        return issue_number
                    else:
                        logger.error(f"Failed to create issue: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"Failed to create issue: {e}")
            return None
    
    async def _get_tree(self, owner: str, repo: str, branch: str) -> List[Dict[str, Any]]:
        """Get repository tree."""
        try:
            async with aiohttp.ClientSession() as session:
                # Get branch SHA
                ref_url = f"{self.api_base}/repos/{owner}/{repo}/git/ref/heads/{branch}"
                async with session.get(ref_url, headers=self.headers) as response:
                    ref_data = await response.json()
                    sha = ref_data['object']['sha']
                
                # Get tree
                tree_url = f"{self.api_base}/repos/{owner}/{repo}/git/trees/{sha}?recursive=1"
                async with session.get(tree_url, headers=self.headers) as response:
                    tree_data = await response.json()
                    return tree_data.get('tree', [])
        
        except Exception as e:
            logger.error(f"Failed to get tree: {e}")
            return []
    
    async def _get_file_content(self, owner: str, repo: str, path: str, branch: str) -> str:
        """Get file content."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}/contents/{path}?ref={branch}"
                
                async with session.get(url, headers=self.headers) as response:
                    data = await response.json()
                    
                    if 'content' in data:
                        # Decode base64 content
                        content = base64.b64decode(data['content']).decode('utf-8')
                        return content
                    
                    return ""
        
        except Exception as e:
            logger.warning(f"Failed to get file content for {path}: {e}")
            return ""
    
    async def _get_security_alerts(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Get Dependabot security alerts."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}/vulnerability-alerts"
                
                headers = {**self.headers, "Accept": "application/vnd.github.dorian-preview+json"}
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 204:
                        # Alerts are enabled but none found
                        return []
                    elif response.status == 200:
                        return await response.json()
                    else:
                        return []
        
        except Exception as e:
            logger.warning(f"Failed to get security alerts: {e}")
            return []
    
    async def _check_branch_protection(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        """Check branch protection rules."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}/branches/{branch}/protection"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "enabled": True,
                            "require_pull_request_reviews": data.get('required_pull_request_reviews') is not None,
                            "require_status_checks": data.get('required_status_checks') is not None,
                            "enforce_admins": data.get('enforce_admins', {}).get('enabled', False)
                        }
                    else:
                        return {"enabled": False}
        
        except Exception as e:
            logger.warning(f"Failed to check branch protection: {e}")
            return {"enabled": False}
    
    def _is_code_file(self, path: str) -> bool:
        """Check if file is a code file."""
        code_extensions = {
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', 
            '.cs', '.cpp', '.c', '.h', '.rs', '.kt', '.swift'
        }
        
        return any(path.endswith(ext) for ext in code_extensions)
