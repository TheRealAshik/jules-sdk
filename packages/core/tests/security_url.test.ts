/**
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, it, expect } from 'vitest';
import { JulesApiError, JulesNetworkError, JulesAuthenticationError, JulesRateLimitError } from '../src/errors.js';

describe('Security: URL Sanitization in Errors', () => {
  const sensitiveUrl = 'https://api.example.com/v1/data?token=secret-token&apiKey=12345&pageToken=pg123#internal-fragment';
  const expectedSanitizedUrl = 'https://api.example.com/v1/data?pageToken=pg123';

  it('JulesNetworkError should sanitize URL in message and property', () => {
    const error = new JulesNetworkError(sensitiveUrl);
    expect(error.url).not.toContain('secret-token');
    expect(error.message).not.toContain('secret-token');
    expect(error.url).not.toContain('12345');
    expect(error.message).not.toContain('12345');
    // We expect it to be sanitized but preserve non-sensitive params
    expect(error.url).toBe(expectedSanitizedUrl);
  });

  it('JulesApiError should sanitize URL in message and property', () => {
    const error = new JulesApiError(sensitiveUrl, 500, 'Internal Server Error');
    expect(error.url).not.toContain('secret-token');
    expect(error.message).not.toContain('secret-token');
    expect(error.url).toBe(expectedSanitizedUrl);
  });

  it('JulesAuthenticationError should sanitize URL in message and property', () => {
    const error = new JulesAuthenticationError(sensitiveUrl, 401, 'Unauthorized');
    expect(error.url).not.toContain('secret-token');
    expect(error.message).not.toContain('secret-token');
    expect(error.url).toBe(expectedSanitizedUrl);
  });

  it('JulesRateLimitError should sanitize URL in message and property', () => {
    const error = new JulesRateLimitError(sensitiveUrl, 429, 'Too Many Requests');
    expect(error.url).not.toContain('secret-token');
    expect(error.message).not.toContain('secret-token');
    expect(error.url).toBe(expectedSanitizedUrl);
  });
});
