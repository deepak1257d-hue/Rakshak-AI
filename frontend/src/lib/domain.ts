/**
 * Domain & URL Normalization Utility
 * Normalizes input domain before sending to AEGIS backend:
 * - Strips protocols (http://, https://, ftp://, etc.)
 * - Strips leading 'www.'
 * - Strips paths, query strings, and fragments
 * - Strips port numbers (:8080, :443, etc.)
 * - Coerces to lowercase
 * - Validates host format with actionable error messages
 */

export interface NormalizedDomainResult {
  domain: string;
  isValid: boolean;
  error?: string;
}

export function normalizeDomain(rawInput: string): NormalizedDomainResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return { domain: '', isValid: false, error: 'Please enter a website domain or URL.' };
  }

  let cleaned = rawInput.trim().toLowerCase();

  // 1. Strip protocol if present
  cleaned = cleaned.replace(/^[a-z]+:\/\//, '');

  // 2. Strip credentials if present (user:pass@)
  if (cleaned.includes('@')) {
    cleaned = cleaned.split('@')[1];
  }

  // 3. Strip path, query params, and hash fragments
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split('?')[0];
  cleaned = cleaned.split('#')[0];

  // 4. Strip port number (:3000, :8443, etc.)
  if (cleaned.includes(':')) {
    cleaned = cleaned.split(':')[0];
  }

  // 5. Strip leading 'www.'
  if (cleaned.startsWith('www.')) {
    cleaned = cleaned.slice(4);
  }

  // Remove trailing dots
  cleaned = cleaned.replace(/\.+$/, '');

  if (!cleaned) {
    return { domain: '', isValid: false, error: 'Domain cannot be empty.' };
  }

  // Allow localhost or standard IP addresses or domain names with at least one dot
  const isLocalhost = cleaned === 'localhost';
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleaned);
  const isStandardDomain = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleaned);

  if (!isLocalhost && !isIpAddress && !isStandardDomain) {
    return {
      domain: cleaned,
      isValid: false,
      error: 'Invalid domain format. Please enter a valid domain (e.g., example.com or app.internal.net).'
    };
  }

  return {
    domain: cleaned,
    isValid: true
  };
}
