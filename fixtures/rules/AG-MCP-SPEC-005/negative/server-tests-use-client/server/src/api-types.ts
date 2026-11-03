// Generated from the provider's OpenAPI document.
export interface TokenRequest {
  /**
   * @example {
   *   "grant_type": "authorization_code",
   *   "code": "abc"
   * }
   */
  grant_type?: "authorization_code" | "refresh_token";
  code?: string;
}
