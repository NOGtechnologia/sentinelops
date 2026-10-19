import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client";
import {
  useCreateSource,
  useCreateToken,
  useDeleteSource,
  useRevokeToken,
  useSettings,
  useSources,
  useTokens,
  useTriggerAnalysis,
  useUsers,
} from "../api/hooks";
import { Tag } from "../components/Badges";
import { PageHeader, Section } from "../components/Layout";
import { QueryView } from "../components/States";
import { Time } from "../components/Time";

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.detail : String(error);
}

export function AdminPage() {
  const { t } = useTranslation();
  const analysis = useTriggerAnalysis();
  return (
    <>
      <PageHeader
        title={t("admin.title")}
        actions={
          <button
            type="button"
            className="btn"
            disabled={analysis.isPending}
            onClick={() => {
              analysis.mutate();
            }}
          >
            {t("admin.runAnalysis")}
          </button>
        }
        subtitle={analysis.data ? t("admin.analysisQueued", { id: analysis.data.job_id }) : t("admin.subtitle")}
      />
      <div className="grid gap-4 xl:grid-cols-2">
        <TokensSection />
        <SourcesSection />
        <UsersSection />
        <SettingsSection />
      </div>
    </>
  );
}

function TokensSection() {
  const { t } = useTranslation();
  const query = useTokens();
  const create = useCreateToken();
  const revoke = useRevokeToken();
  const [name, setName] = useState("");
  return (
    <Section title={t("admin.tokens")}>
      <form
        className="mb-3 flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(name.trim(), {
            onSuccess: () => {
              setName("");
            },
          });
        }}
      >
        <label htmlFor="token-name" className="sr-only">
          {t("admin.tokenName")}
        </label>
        <input
          id="token-name"
          className="input"
          placeholder={t("admin.tokenName")}
          value={name}
          minLength={3}
          onChange={(event) => {
            setName(event.target.value);
          }}
        />
        <button type="submit" className="btn" disabled={name.trim().length < 3 || create.isPending}>
          {t("admin.createToken")}
        </button>
      </form>
      {create.data && (
        <div role="status" className="mb-3 rounded-md border border-warn/50 bg-warn/10 p-3 text-sm">
          <p className="font-semibold">{t("admin.tokenOnce")}</p>
          <code className="mt-1 block font-mono text-xs break-all">{create.data.token}</code>
        </div>
      )}
      {create.error && <p className="mb-2 text-sm text-danger">{errorText(create.error)}</p>}
      <QueryView query={query} empty={(rows) => rows.length === 0}>
        {(rows) => (
          <ul className="flex flex-col gap-1.5 text-sm">
            {rows.map((token) => (
              <li key={token.token_id} className="flex items-center justify-between gap-2">
                <span>
                  {token.name} <span className="font-mono text-xs text-muted">{token.token_id}</span>
                </span>
                {token.revoked_at ? (
                  <Tag>{t("admin.revoked")}</Tag>
                ) : (
                  <button
                    type="button"
                    className="btn btn-sm btn-danger"
                    onClick={() => {
                      revoke.mutate(token.token_id);
                    }}
                  >
                    {t("admin.revoke")}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Section>
  );
}

function SourcesSection() {
  const { t } = useTranslation();
  const query = useSources();
  const create = useCreateSource();
  const remove = useDeleteSource();
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [timezone, setTimezone] = useState("Europe/Berlin");
  const types = query.data?.source_types ?? [];
  return (
    <Section title={t("admin.sources")}>
      <form
        className="mb-3 grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate({ name: name.trim(), source_type: sourceType || (types[0] ?? ""), timezone });
        }}
      >
        <label className="sr-only" htmlFor="source-name">
          {t("admin.sourceName")}
        </label>
        <input
          id="source-name"
          className="input"
          placeholder={t("admin.sourceName")}
          value={name}
          onChange={(event) => {
            setName(event.target.value);
          }}
        />
        <label className="sr-only" htmlFor="source-type">
          {t("quality.sourceType")}
        </label>
        <select
          id="source-type"
          className="input font-mono"
          value={sourceType || (types[0] ?? "")}
          onChange={(event) => {
            setSourceType(event.target.value);
          }}
        >
          {types.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
        <label className="sr-only" htmlFor="source-tz">
          {t("quality.timezone")}
        </label>
        <input
          id="source-tz"
          className="input"
          value={timezone}
          onChange={(event) => {
            setTimezone(event.target.value);
          }}
        />
        <button type="submit" className="btn" disabled={!name.trim() || create.isPending}>
          {t("admin.addSource")}
        </button>
      </form>
      {create.error && <p className="mb-2 text-sm text-danger">{errorText(create.error)}</p>}
      <QueryView query={query}>
        {(data) =>
          data.items.length === 0 ? (
            <p className="text-sm text-muted">{t("admin.noSources")}</p>
          ) : (
            <ul className="flex flex-col gap-1.5 text-sm">
              {data.items.map((source) => (
                <li key={source.source_id} className="flex items-center justify-between gap-2">
                  <span>
                    {source.name}{" "}
                    <span className="font-mono text-xs text-muted">
                      {source.source_type} · {source.timezone}
                    </span>
                  </span>
                  <button
                    type="button"
                    className="btn btn-sm btn-danger"
                    onClick={() => {
                      remove.mutate(source.source_id);
                    }}
                  >
                    {t("admin.remove")}
                  </button>
                </li>
              ))}
            </ul>
          )
        }
      </QueryView>
    </Section>
  );
}

function UsersSection() {
  const { t } = useTranslation();
  const query = useUsers();
  return (
    <Section title={t("admin.users")} aside={t("admin.usersHint")}>
      <QueryView query={query}>
        {(rows) => (
          <table className="table text-sm">
            <thead>
              <tr>
                <th scope="col">{t("admin.user")}</th>
                <th scope="col">{t("admin.roles")}</th>
                <th scope="col">{t("admin.lastLogin")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((user) => (
                <tr key={user.subject}>
                  <td>
                    {user.display_name}
                    <p className="font-mono text-xs text-muted">{user.username}</p>
                  </td>
                  <td className="text-xs">{user.roles.map((r) => t(`roles.${r}`)).join(", ")}</td>
                  <td className="text-xs">
                    <Time value={user.last_login} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </QueryView>
    </Section>
  );
}

function SettingsSection() {
  const { t } = useTranslation();
  const query = useSettings();
  return (
    <Section title={t("admin.settings")} aside={t("admin.settingsHint")}>
      <QueryView query={query}>
        {(data) => (
          <pre tabIndex={0} className="raw-line max-h-96 overflow-auto rounded-md bg-code p-3">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}
      </QueryView>
    </Section>
  );
}
