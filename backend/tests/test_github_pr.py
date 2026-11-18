import pytest
from unittest.mock import patch, AsyncMock
import httpx
from app.mcp.servers.github_server import create_pull_request, _validate_repo_name, _sanitize_branch_name

def test_repo_name_validation():
    assert _validate_repo_name("octocat/Hello-World") == ("octocat", "Hello-World")
    assert _validate_repo_name("my-org/repo_name.js") == ("my-org", "repo_name.js")
    assert _validate_repo_name("invalid_no_slash") is None
    assert _validate_repo_name("invalid/with/extra/slash") is None
    assert _validate_repo_name("invalid;injection/repo") is None
    assert _validate_repo_name("") is None

def test_sanitize_branch_name():
    assert _sanitize_branch_name("CVE-2023-1234") == "CVE-2023-1234"
    assert _sanitize_branch_name("SQL Injection in /api/v1/users") == "SQL-Injection-in-api-v1-users"

@pytest.mark.asyncio
async def test_pr_creation_unavailable_without_token():
    with patch("app.mcp.servers.github_server._get_github_token", return_value=None):
        res = await create_pull_request(
            repo_name="myorg/secure-app",
            finding_title="SQL Injection",
            remediation_patch="--- a/db.py\n+++ b/db.py\n@@ ...",
        )
        assert res["status"] == "UNAVAILABLE"
        assert "GITHUB_TOKEN" in res["error"]

@pytest.mark.asyncio
async def test_pr_creation_error_empty_patch():
    with patch("app.mcp.servers.github_server._get_github_token", return_value="ghp_testtoken"):
        res = await create_pull_request(
            repo_name="myorg/secure-app",
            finding_title="SQL Injection",
            remediation_patch="   ",
        )
        assert res["status"] == "ERROR"
        assert "patch" in res["error"].lower()

@pytest.mark.asyncio
async def test_pr_creation_invalid_repo_format():
    with patch("app.mcp.servers.github_server._get_github_token", return_value="ghp_testtoken"):
        res = await create_pull_request(
            repo_name="invalid-repo-without-owner",
            finding_title="SQL Injection",
            remediation_patch="diff --git a/a b/b",
        )
        assert res["status"] == "ERROR"
        assert "format" in res["error"].lower()

@pytest.mark.asyncio
async def test_pr_creation_auth_failure():
    with patch("app.mcp.servers.github_server._get_github_token", return_value="ghp_invalid_token"):
        mock_response = httpx.Response(401, json={"message": "Bad credentials"})
        with patch("httpx.AsyncClient.get", return_value=mock_response):
            res = await create_pull_request(
                repo_name="myorg/secure-app",
                finding_title="SQL Injection",
                remediation_patch="diff --git a/a b/b",
            )
            assert res["status"] == "ERROR"
            assert "authentication failed" in res["error"].lower()

@pytest.mark.asyncio
async def test_pr_creation_duplicate_detected():
    with patch("app.mcp.servers.github_server._get_github_token", return_value="ghp_valid_token"):
        async def mock_get(url, *args, **kwargs):
            if "/repos/myorg/secure-app/pulls" in url:
                return httpx.Response(200, json=[{
                    "html_url": "https://github.com/myorg/secure-app/pull/42",
                    "number": 42
                }])
            if "/repos/myorg/secure-app" in url:
                return httpx.Response(200, json={"default_branch": "main"})
            return httpx.Response(404)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            res = await create_pull_request(
                repo_name="myorg/secure-app",
                finding_title="SQL Injection",
                remediation_patch="diff --git a/a b/b",
                cve_id="CVE-2023-9999"
            )
            assert res["status"] == "DUPLICATE"
            assert res["pr_url"] == "https://github.com/myorg/secure-app/pull/42"
            assert res["pr_number"] == 42

@pytest.mark.asyncio
async def test_pr_creation_success_lifecycle():
    with patch("app.mcp.servers.github_server._get_github_token", return_value="ghp_valid_token"):
        async def mock_get(url, *args, **kwargs):
            if url.endswith("/repos/myorg/secure-app"):
                return httpx.Response(200, json={"default_branch": "main"})
            if "/pulls" in url:
                return httpx.Response(200, json=[])
            if "/git/ref/heads/main" in url:
                return httpx.Response(200, json={"object": {"sha": "base123sha"}})
            if "/contents/" in url:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(404)

        async def mock_post(url, *args, **kwargs):
            if "/git/refs" in url:
                return httpx.Response(201, json={"ref": "refs/heads/aegis/remediation-CVE-2024-1111"})
            if "/pulls" in url:
                return httpx.Response(201, json={
                    "html_url": "https://github.com/myorg/secure-app/pull/101",
                    "number": 101,
                    "title": "fix(security): [CVE-2024-1111] Remote Code Execution",
                })
            return httpx.Response(400)

        async def mock_put(url, *args, **kwargs):
            if "/contents/" in url:
                return httpx.Response(201, json={"content": {"sha": "filesha123"}})
            return httpx.Response(400)

        with patch("httpx.AsyncClient.get", side_effect=mock_get), \
             patch("httpx.AsyncClient.post", side_effect=mock_post), \
             patch("httpx.AsyncClient.put", side_effect=mock_put):
            res = await create_pull_request(
                repo_name="myorg/secure-app",
                finding_title="Remote Code Execution",
                remediation_patch="diff --git a/app.py b/app.py\n+secure_code()",
                cve_id="CVE-2024-1111"
            )
            assert res["status"] == "SUCCESS"
            assert res["pr_url"] == "https://github.com/myorg/secure-app/pull/101"
            assert res["pr_number"] == 101
            assert res["auto_merge_disabled"] is True
