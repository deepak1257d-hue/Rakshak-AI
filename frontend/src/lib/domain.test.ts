// Regression tests for: next@14.1.0 upgrade
import { describe, expect, it } from 'vitest';
import { normalizeDomain } from './domain';

describe('normalizeDomain', () => {
  it('normalizes a website URL to a lowercase host', () => {
    expect(normalizeDomain('HTTPS://WWW.Example.com:8443/path?ref=1')).toEqual({
      domain: 'example.com',
      isValid: true
    });
  });

  it('rejects malformed host names', () => {
    expect(normalizeDomain('not a domain')).toMatchObject({
      domain: 'not a domain',
      isValid: false
    });
  });
});
