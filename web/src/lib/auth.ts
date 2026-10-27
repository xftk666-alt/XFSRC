// Session handling.
//
// The JWT lives in an HttpOnly, SameSite=Strict cookie set by the Go backend
// (/api/auth/login, /api/auth/init). Page scripts therefore cannot read it, so an
// XSS cannot exfiltrate a 7-day admin token — which is the whole point of moving
// it out of localStorage.
//
// What remains in the browser is a NON-SECRET marker: it only tells the
// client-side route guard that a session is expected, so protected UI can render
// instead of flashing the login page. Every request is authorised by the cookie
// server-side; forging the marker gets you a UI that immediately 401s.
const SESSION_MARKER = "xfsrc_session";
// Legacy key from the localStorage-token era; removed on sight.
const LEGACY_TOKEN_KEY = "artex_token";

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

function clearLegacyToken(): void {
  try {
    localStorage.removeItem(LEGACY_TOKEN_KEY);
    // Older builds also mirrored the token into a JS-readable cookie.
    document.cookie = `${LEGACY_TOKEN_KEY}=; path=/; max-age=0`;
  } catch {
    // localStorage can throw in private mode; nothing to clean up then.
  }
}

export const auth = {
  /** True when a session is expected. Carries no credential. */
  hasSession(): boolean {
    if (typeof window === "undefined") return false;
    if (process.env.NEXT_PUBLIC_MOCK === "1") return true;
    return localStorage.getItem(SESSION_MARKER) === "1";
  },

  /**
   * Called after a successful login/init. The server already set the HttpOnly
   * cookie on the response; here we only record that a session exists.
   */
  setToken(_token: string): void {
    clearLegacyToken();
    try {
      localStorage.setItem(SESSION_MARKER, "1");
    } catch {
      // Non-fatal: the route guard will fall back to the login page.
    }
  },

  /** Local-only cleanup (expired session, 401). Does NOT revoke the cookie. */
  clearToken(): void {
    try {
      localStorage.removeItem(SESSION_MARKER);
    } catch {
      // ignore
    }
    clearLegacyToken();
  },

  /**
   * Real logout: revokes every issued token server-side (the JWT generation is
   * bumped) and clears the cookie, then drops the local marker.
   */
  async logout(): Promise<void> {
    try {
      await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    } catch {
      // Offline / server down: still clear local state below.
    }
    this.clearToken();
  },

  getCurrentUser(): CurrentUser | null {
    if (!this.hasSession()) return null;
    // The username is fixed by the backend (single admin account).
    const username = "XFSRC";
    return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
  },
};
