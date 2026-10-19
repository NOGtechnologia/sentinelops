import { KeyRound, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useAuth } from "../auth/AuthProvider";
import { Logo } from "../components/Logo";

export function LoginPage() {
  const { t } = useTranslation();
  const { config, loginDemo, loginOidc, error } = useAuth();
  const [busy, setBusy] = useState<string | null>(null);

  return (
    <main className="flex min-h-full items-center justify-center p-4">
      <div className="card w-full max-w-md p-6">
        <div className="mb-6 flex items-center gap-3">
          <Logo className="size-10" />
          <div>
            <h1 className="text-xl font-bold">{t("app.name")}</h1>
            <p className="text-sm text-muted">{t("app.tagline")}</p>
          </div>
        </div>

        {error && (
          <p role="alert" className="mb-4 rounded-md border border-danger/40 bg-danger/5 p-3 text-sm text-danger">
            {t("auth.failed")}
          </p>
        )}

        {config?.oidc_issuer && (
          <button
            type="button"
            className="btn btn-primary w-full"
            onClick={() => {
              setBusy("oidc");
              void loginOidc();
            }}
            disabled={busy !== null}
          >
            <KeyRound aria-hidden className="size-4" />
            {t("auth.loginOidc")}
          </button>
        )}

        {config?.demo_mode && (
          <section aria-labelledby="demo-heading" className="mt-6">
            <div className="mb-3 flex items-start gap-2 rounded-md border border-warn/50 bg-warn/10 p-3 text-sm">
              <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-warn" />
              <div>
                <h2 id="demo-heading" className="font-semibold text-warn">
                  {t("auth.demoTitle")}
                </h2>
                <p className="text-muted">{t("auth.demoHint")}</p>
              </div>
            </div>
            <ul className="flex flex-col gap-2">
              {config.demo_users.map((user) => (
                <li key={user.id}>
                  <button
                    type="button"
                    className="btn w-full justify-between"
                    disabled={busy !== null}
                    onClick={() => {
                      setBusy(user.id);
                      void loginDemo(user.id).finally(() => {
                        setBusy(null);
                      });
                    }}
                    data-testid={`demo-login-${user.id}`}
                  >
                    <span>{user.name}</span>
                    <span className="text-xs font-normal text-muted">
                      {user.roles.map((r) => t(`roles.${r}`)).join(", ")}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}

        {!config?.oidc_issuer && !config?.demo_mode && <p className="text-sm text-muted">{t("auth.notConfigured")}</p>}

        <p className="mt-6 text-xs text-muted">{t("app.complements")}</p>
      </div>
    </main>
  );
}
