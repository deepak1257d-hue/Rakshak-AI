from typing import Dict, Any, Optional

class GitHubRemediationService:
    """
    GitHub PR dispatch is unavailable until a real GitHub API integration is implemented.
    """
    @staticmethod
    def dispatch_pull_request(
        repo_name: str,
        finding_title: str,
        remediation_patch: str,
        cve_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "status": "UNAVAILABLE",
            "error": "GitHub pull request dispatch is not implemented; no pull request was created.",
        }

github_remediation_service = GitHubRemediationService()
