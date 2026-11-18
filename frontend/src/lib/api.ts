import { TargetAsset, ScanRun, Finding, ExecutiveSummary } from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE?.trim().replace(/\/+$/, '');
if (!API_BASE) {
  throw new Error('NEXT_PUBLIC_API_BASE must be set in the frontend environment.');
}

const apiBaseUrl = new URL(API_BASE);
const WEBSOCKET_BASE = `${apiBaseUrl.protocol === 'https:' ? 'wss:' : 'ws:'}//${apiBaseUrl.host}${apiBaseUrl.pathname.replace(/\/+$/, '')}`;

export interface AuthUser {
  user_id: string;
  email: string;
  role: string;
  workspace_id: string;
}

export interface ApprovalDecisionResult {
  success: boolean;
  action: 'APPROVED' | 'REJECTED';
  approver?: string;
  approver_id?: string;
  auto_merge_disabled?: boolean;
  pr_url?: string | null;
  branch_name?: string | null;
  message?: string;
}

export class AegisApiClient {
  private token: string | null = null;
  private user: AuthUser | null = null;

  constructor() {
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('aegis_token');
      const savedUser = localStorage.getItem('aegis_user');
      if (savedUser) {
        try {
          this.user = JSON.parse(savedUser);
        } catch {
          this.user = null;
        }
      }
    }
  }

  setToken(token: string, user?: AuthUser) {
    this.token = token;
    if (typeof window !== 'undefined') {
      localStorage.setItem('aegis_token', token);
      if (user) {
        this.user = user;
        localStorage.setItem('aegis_user', JSON.stringify(user));
      }
    }
  }

  getToken(): string | null {
    if (!this.token && typeof window !== 'undefined') {
      this.token = localStorage.getItem('aegis_token');
    }
    return this.token;
  }

  getUser(): AuthUser | null {
    if (!this.user && typeof window !== 'undefined') {
      const saved = localStorage.getItem('aegis_user');
      if (saved) {
        try {
          this.user = JSON.parse(saved);
        } catch {
          this.user = null;
        }
      }
    }
    return this.user;
  }

  isAuthenticated(): boolean {
    return Boolean(this.getToken());
  }

  logout() {
    this.token = null;
    this.user = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('aegis_token');
      localStorage.removeItem('aegis_user');
    }
  }

  private getHeaders(): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json'
    };
    const t = this.getToken();
    if (t) {
      headers['Authorization'] = `Bearer ${t}`;
    }
    return headers;
  }

  // --- Auth Endpoints ---

  async register(email: string, password: string, workspaceName: string) {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, workspace_name: workspaceName })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Registration failed' }));
      throw new Error(err.detail || 'Registration failed');
    }
    const data = await res.json();
    this.setToken(data.access_token, {
      user_id: data.user_id,
      email: data.email,
      role: data.role,
      workspace_id: data.workspace_id
    });
    return data;
  }

  async login(email: string, password: string) {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);

    const res = await fetch(`${API_BASE}/auth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData.toString()
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Invalid credentials' }));
      throw new Error(err.detail || 'Incorrect email or password.');
    }

    const data = await res.json();
    this.setToken(data.access_token, {
      user_id: data.user_id,
      email: data.email,
      role: data.role,
      workspace_id: data.workspace_id
    });
    return data;
  }

  // --- Target Asset Endpoints ---

  async listTargets(): Promise<TargetAsset[]> {
    const res = await fetch(`${API_BASE}/targets`, { headers: this.getHeaders() });
    if (!res.ok) {
      if (res.status === 401) {
        this.logout();
        throw new Error('Session expired. Please log in again.');
      }
      throw new Error('Failed to fetch targets from backend');
    }
    return res.json();
  }

  async getTarget(targetId: string): Promise<TargetAsset | null> {
    const res = await fetch(`${API_BASE}/targets/${targetId}`, { headers: this.getHeaders() });
    if (res.status === 404) {
      return null;
    }
    if (res.status === 401) {
      this.logout();
      throw new Error('Session expired. Please log in again.');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({
        detail: `Failed to fetch target (HTTP ${res.status})`
      }));
      throw new Error(err.detail || 'Failed to fetch target');
    }
    return res.json();
  }

  async createTarget(domain: string, verificationMethod: 'DNS_TXT' | 'HTML_META' | 'HTTP_FILE' = 'DNS_TXT'): Promise<TargetAsset> {
    const res = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ domain, verification_method: verificationMethod })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add website' }));
      throw new Error(err.detail || 'Failed to add website');
    }
    return res.json();
  }

  async verifyTarget(targetId: string, method: 'DNS_TXT' | 'HTML_META' | 'HTTP_FILE' | 'LAB'): Promise<TargetAsset> {
    const res = await fetch(`${API_BASE}/targets/${targetId}/verify`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ method })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Target verification failed' }));
      throw new Error(err.detail || 'Target verification failed');
    }
    return res.json();
  }


  // --- Scan helper endpoints (added for Rakshak AI UI) ---
  // listScanFindings: per-scan findings (distinct from global listFindings below)
  async listScanFindings(scanId: string): Promise<Finding[]> {
    const res = await fetch(`${API_BASE}/scans/${scanId}/findings`, { headers: this.getHeaders() });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to load findings' }));
      throw new Error(err.detail || 'Failed to load findings');
    }
    return res.json();
  }

  async listScans(): Promise<ScanRun[]> {
    const res = await fetch(`${API_BASE}/scans`, { headers: this.getHeaders() });
    if (!res.ok) {
      if (res.status === 401) {
        this.logout();
        throw new Error('Session expired. Please log in again.');
      }
      throw new Error('Failed to fetch scan history');
    }
    return res.json();
  }

  async launchScan(targetId: string): Promise<ScanRun> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ target_id: targetId })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to launch scan' }));
      throw new Error(err.detail || 'Failed to launch scan');
    }
    return res.json();
  }

  async getScan(scanId: string): Promise<ScanRun> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      if (res.status === 401) {
        this.logout();
        throw new Error('Session expired. Please log in again.');
      }
      const err = await res.json().catch(() => ({
        detail: `Failed to fetch scan status (HTTP ${res.status})`
      }));
      throw new Error(err.detail || 'Failed to fetch scan status');
    }
    return res.json();
  }

  async getExecutiveSummary(scanId: string): Promise<ExecutiveSummary> {
    const res = await fetch(`${API_BASE}/reports/executive-summary/${scanId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      if (res.status === 401) {
        this.logout();
        throw new Error('Session expired. Please log in again.');
      }
      const err = await res.json().catch(() => ({ detail: 'Failed to fetch executive report' }));
      throw new Error(err.detail || 'Failed to fetch executive report');
    }
    return res.json();
  }

  async listFindings(): Promise<Finding[]> {
    const res = await fetch(`${API_BASE}/reports/findings`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to fetch findings' }));
      throw new Error(err.detail || 'Failed to fetch findings');
    }
    return res.json();
  }

  // --- HITL Remediation Endpoints ---

  async submitApprovalDecision(
    findingId: string,
    action: 'APPROVE' | 'REJECT',
    repoName?: string,
    threadId?: string,
    notes?: string
  ): Promise<ApprovalDecisionResult> {
    const res = await fetch(`${API_BASE}/reports/remediate/decision`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        finding_id: findingId,
        action: action,
        ...(repoName ? { repo_name: repoName } : {}),
        thread_id: threadId,
        notes: notes
      })
    });
    if (!res.ok) {
      if (res.status === 401) {
        this.logout();
        throw new Error('Session expired. Please log in again.');
      }
      const err = await res.json().catch(() => ({ detail: 'Failed to submit remediation decision' }));
      throw new Error(err.detail || 'Failed to submit remediation decision');
    }
    const result = await res.json() as ApprovalDecisionResult;
    const expectedAction = action === 'APPROVE' ? 'APPROVED' : 'REJECTED';
    if (!result.success || result.action !== expectedAction) {
      throw new Error(result.message || 'The backend did not confirm the requested decision.');
    }
    return result;
  }

  connectScanWebSocket(scanId: string, onMessage: (data: any) => void): WebSocket {
    const token = this.getToken();
    if (!token) {
      throw new Error('Authentication is required for live scan updates.');
    }
    const ws = new WebSocket(
      `${WEBSOCKET_BASE}/scans/${scanId}/ws`,
      ['aegis', `aegis.bearer.${token}`]
    );
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (e) {
        console.error('WebSocket parse error:', e);
      }
    };
    return ws;
  }
}

export const aegisApi = new AegisApiClient();
