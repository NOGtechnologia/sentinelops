import { useQueryClient } from "@tanstack/react-query";
import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { api, setAccessToken, setUnauthorizedHandler } from "../api/client";
import { useAuthConfig } from "../api/hooks";
import type { AuthConfig, Me } from "../api/types";
import { setDisplayZone } from "../lib/format";

// Only a non-secret hint is kept across reloads: which demo user was chosen, or that an OIDC login
// happened (to resume it with the IdP's single sign-on). Tokens never leave memory.
const DEMO_HINT = "sentinelops.demoUser";
const OIDC_HINT = "sentinelops.oidcLogin";

export type AuthStatus = "loading" | "anonymous" | "authenticated";

export interface AuthState {
  status: AuthStatus;
  me: Me | null;
  config: AuthConfig | null;
  error: string | null;
  can: (permission: string) => boolean;
  loginDemo: (user: string) => Promise<void>;
  loginOidc: () => Promise<void>;
  completeOidc: () => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

function readHint(key: string): string | null {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeHint(key: string, value: string | null): void {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, value);
  } catch {
    // storage unavailable (private mode) - the user simply logs in again after a reload
  }
}

function userManagerFor(config: AuthConfig): UserManager | null {
  if (!config.oidc_issuer) return null;
  return new UserManager({
    authority: config.oidc_issuer,
    client_id: config.oidc_client_id,
    redirect_uri: `${window.location.origin}/auth/callback`,
    post_logout_redirect_uri: `${window.location.origin}/`,
    response_type: "code",
    scope: "openid profile",
    automaticSilentRenew: true,
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const config = useAuthConfig();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const managerRef = useRef<UserManager | null>(null);

  const finish = useCallback(async (token: string) => {
    setAccessToken(token);
    const profile = await api<Me>("/api/v1/auth/me");
    setMe(profile);
    setStatus("authenticated");
    setError(null);
  }, []);

  const reset = useCallback(() => {
    setAccessToken(null);
    setMe(null);
    setStatus("anonymous");
    queryClient.clear();
  }, [queryClient]);

  const loginDemo = useCallback(
    async (user: string) => {
      try {
        const result = await api<{ access_token: string }>("/api/v1/auth/demo-login", {
          method: "POST",
          body: { user },
        });
        writeHint(DEMO_HINT, user);
        await finish(result.access_token);
      } catch (exc) {
        writeHint(DEMO_HINT, null);
        setError(exc instanceof Error ? exc.message : String(exc));
        setStatus("anonymous");
      }
    },
    [finish],
  );

  const loginOidc = useCallback(async () => {
    if (!managerRef.current) return;
    writeHint(OIDC_HINT, "1");
    await managerRef.current.signinRedirect();
  }, []);

  const completeOidc = useCallback(async () => {
    if (!managerRef.current) return;
    try {
      const user: User = await managerRef.current.signinRedirectCallback();
      window.history.replaceState({}, "", "/");
      await finish(user.access_token);
    } catch (exc) {
      writeHint(OIDC_HINT, null);
      setError(exc instanceof Error ? exc.message : String(exc));
      setStatus("anonymous");
    }
  }, [finish]);

  const logout = useCallback(() => {
    const manager = managerRef.current;
    const wasOidc = readHint(OIDC_HINT) === "1";
    writeHint(DEMO_HINT, null);
    writeHint(OIDC_HINT, null);
    reset();
    if (manager && wasOidc) void manager.signoutRedirect();
  }, [reset]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      if (status === "authenticated") reset();
    });
    return () => {
      setUnauthorizedHandler(null);
    };
  }, [reset, status]);

  // Initialise once the public auth configuration is known.
  const initialised = useRef(false);
  useEffect(() => {
    const data = config.data;
    if (!data || initialised.current) return;
    initialised.current = true;
    setDisplayZone(data.display_timezone);
    const manager = userManagerFor(data);
    managerRef.current = manager;
    if (manager) {
      manager.events.addUserLoaded((user) => {
        setAccessToken(user.access_token);
      });
    }
    const start = async () => {
      if (window.location.pathname === "/auth/callback") {
        await completeOidc();
        return;
      }
      const demoUser = readHint(DEMO_HINT);
      if (data.demo_mode && demoUser) {
        await loginDemo(demoUser);
        return;
      }
      if (manager && readHint(OIDC_HINT) === "1") {
        await manager.signinRedirect();
        return;
      }
      setStatus("anonymous");
    };
    void start();
  }, [config.data, completeOidc, loginDemo]);

  // Without the public configuration nobody can sign in: show the login page with the error.
  const effectiveStatus: AuthStatus = config.error && status === "loading" ? "anonymous" : status;
  const effectiveError = error ?? (config.error ? config.error.message : null);

  const value = useMemo<AuthState>(
    () => ({
      status: effectiveStatus,
      me,
      config: config.data ?? null,
      error: effectiveError,
      can: (permission: string) => me?.permissions.includes(permission) ?? false,
      loginDemo,
      loginOidc,
      completeOidc,
      logout,
    }),
    [effectiveStatus, me, config.data, effectiveError, loginDemo, loginOidc, completeOidc, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth outside AuthProvider");
  return value;
}
