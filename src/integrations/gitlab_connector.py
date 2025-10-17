"""GitLab integration for code compliance scanning."""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import aiohttp

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GitLabProject:
    """GitLab project information."""
    
    id: int
    name: str
    path: str
    default_branch: str
    url: str
    visibility: str


class GitLabConnector:
    """
    GitLab integration for compliance scanning.
    
    Features:
    - Project scanning
    - Merge request analysis
    - Commit compliance checks
    - Security dashboard integration
    - Automated MR comments
    - CI/CD pipeline integration
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize GitLab connector."""
        self.config = config or {}
        self.token = config.get('gitlab_token') or os.getenv('GITLAB_TOKEN')
        self.api_base = config.get('gitlab_url', 'https://gitlab.com') + '/api/v4'
        self.headers = {
            "PRIVATE-TOKEN": self.token
        }
    
    async def get_project(self, project_id: str) -> GitLabProject:
        """Get project information."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to get project: {response.status}")
                    
                    data = await response.json()
                    
                    return GitLabProject(
                        id=data['id'],
                        name=data['name'],
                        path=data['path_with_namespace'],
                        default_branch=data['default_branch'],
                        url=data['web_url'],
                        visibility=data['visibility']
                    )
        
        except Exception as e:
            logger.error(f"Failed to get project {project_id}: {e}")
            raise
    
    async def scan_project(self, project_id: str, branch: Optional[str] = None) -> Dict[str, Any]:
        """Scan entire project for compliance issues."""
        try:
            # Get project info
            project_info = await self.get_project(project_id)
            branch = branch or project_info.default_branch
            
            logger.info(f"Scanning GitLab project {project_id} on branch {branch}")
            
            # Get repository tree
            tree = await self._get_tree(project_id, branch)
            
            # Get security findings
            security_findings = await self._get_security_findings(project_id)
            
            # Get protected branches
            protected_branches = await self._get_protected_branches(project_id)
            
            return {
                "project": {
                    "id": project_id,
                    "name": project_info.name,
                    "path": project_info.path,
                    "branch": branch,
                    "visibility": project_info.visibility
                },
                "files_count": len(tree),
                "security_findings": security_findings,
                "protected_branches": protected_branches
            }
        
        except Exception as e:
            logger.error(f"Failed to scan project: {e}")
            raise
    
    async def scan_merge_request(self, project_id: str, mr_iid: int) -> Dict[str, Any]:
        """Scan merge request for compliance issues."""
        try:
            logger.info(f"Scanning MR !{mr_iid} in project {project_id}")
            
            async with aiohttp.ClientSession() as session:
                # Get MR details
                mr_url = f"{self.api_base}/projects/{project_id}/merge_requests/{mr_iid}"
                async with session.get(mr_url, headers=self.headers) as response:
                    mr_data = await response.json()
                
                # Get MR changes
                changes_url = f"{mr_url}/changes"
                async with session.get(changes_url, headers=self.headers) as response:
                    changes_data = await response.json()
                
                # Get MR commits
                commits_url = f"{mr_url}/commits"
                async with session.get(commits_url, headers=self.headers) as response:
                    commits_data = await response.json()
                
                return {
                    "mr_iid": mr_iid,
                    "title": mr_data['title'],
                    "author": mr_data['author']['name'],
                    "state": mr_data['state'],
                    "source_branch": mr_data['source_branch'],
                    "target_branch": mr_data['target_branch'],
                    "changes": changes_data.get('changes', []),
                    "commits_count": len(commits_data)
                }
        
        except Exception as e:
            logger.error(f"Failed to scan merge request: {e}")
            raise
    
    async def post_mr_comment(self, project_id: str, mr_iid: int, comment: str) -> bool:
        """Post compliance comment on merge request."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}/merge_requests/{mr_iid}/notes"
                
                payload = {"body": comment}
                
                async with session.post(url, headers=self.headers, json=payload) as response:
                    if response.status == 201:
                        logger.info(f"Posted comment on MR !{mr_iid}")
                        return True
                    else:
                        logger.error(f"Failed to post comment: {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Failed to post MR comment: {e}")
            return False
    
    async def create_issue(self, project_id: str, title: str, description: str, labels: Optional[List[str]] = None) -> Optional[int]:
        """Create compliance issue."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}/issues"
                
                payload = {
                    "title": title,
                    "description": description,
                    "labels": ','.join(labels or ["compliance", "security"])
                }
                
                async with session.post(url, headers=self.headers, json=payload) as response:
                    if response.status == 201:
                        data = await response.json()
                        issue_iid = data['iid']
                        logger.info(f"Created issue #{issue_iid}")
                        return issue_iid
                    else:
                        logger.error(f"Failed to create issue: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"Failed to create issue: {e}")
            return None
    
    async def get_ci_pipeline_status(self, project_id: str, pipeline_id: int) -> Dict[str, Any]:
        """Get CI/CD pipeline status."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}/pipelines/{pipeline_id}"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "id": data['id'],
                            "status": data['status'],
                            "ref": data['ref'],
                            "sha": data['sha'],
                            "created_at": data['created_at'],
                            "updated_at": data['updated_at']
                        }
                    else:
                        return {"status": "unknown"}
        
        except Exception as e:
            logger.error(f"Failed to get pipeline status: {e}")
            return {"status": "error"}
    
    async def _get_tree(self, project_id: str, branch: str) -> List[Dict[str, Any]]:
        """Get repository tree."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}/repository/tree"
                params = {"ref": branch, "recursive": "true"}
                
                async with session.get(url, headers=self.headers, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return []
        
        except Exception as e:
            logger.error(f"Failed to get tree: {e}")
            return []
    
    async def _get_security_findings(self, project_id: str) -> List[Dict[str, Any]]:
        """Get security findings from GitLab Security Dashboard."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}/vulnerabilities"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return []
        
        except Exception as e:
            logger.warning(f"Failed to get security findings: {e}")
            return []
    
    async def _get_protected_branches(self, project_id: str) -> List[str]:
        """Get protected branches."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/projects/{project_id}/protected_branches"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return [branch['name'] for branch in data]
                    else:
                        return []
        
        except Exception as e:
            logger.warning(f"Failed to get protected branches: {e}")
            return []
