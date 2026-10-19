import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import i18n, { setLanguage } from "../i18n";
import { apiError, mockApi, renderApp } from "./harness";

describe("login", () => {
  it("shows labelled demo accounts and signs in", async () => {
    const { calls } = mockApi();
    renderApp("/", null);
    expect(await screen.findByText("Demo-Zugänge")).toBeInTheDocument();
    expect(screen.getByText(/Nur im Demo-Modus aktiv/)).toBeInTheDocument();
    await userEvent.click(screen.getByTestId("demo-login-senior"));
    expect(await screen.findByRole("heading", { name: "Lagebild" })).toBeInTheDocument();
    const login = calls.find((c) => c.path === "/api/v1/auth/demo-login");
    expect(login?.body).toEqual({ user: "senior" });
    expect(sessionStorage.getItem("sentinelops.demoUser")).toBe("senior");
  });

  it("reports a failed login", async () => {
    mockApi({ "POST /api/v1/auth/demo-login": apiError(400, "unknown demo user") });
    renderApp("/", null);
    await userEvent.click(await screen.findByTestId("demo-login-analyst"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Anmeldung fehlgeschlagen");
  });

  it("offers OIDC when configured and shows the configuration error", async () => {
    mockApi({
      "GET /api/v1/auth/config": {
        demo_mode: false,
        demo_users: [],
        oidc_issuer: "https://idp.musterfirma.example/realms/sentinelops",
        oidc_client_id: "sentinelops-web",
        display_timezone: "Europe/Berlin",
      },
    });
    renderApp("/", null);
    expect(await screen.findByRole("button", { name: "Mit Unternehmenskonto anmelden" })).toBeEnabled();
    expect(screen.queryByText("Demo-Zugänge")).not.toBeInTheDocument();
  });

  it("falls back to the login page when the configuration cannot be loaded", async () => {
    mockApi({ "GET /api/v1/auth/config": apiError(500, "down") });
    renderApp("/", null);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByText("Es ist keine Anmeldung konfiguriert.")).toBeInTheDocument();
  });
});

describe("shell and dashboard", () => {
  it("renders KPIs with period and data time and links priorities to the queue", async () => {
    mockApi();
    const { router } = renderApp("/");
    expect(await screen.findByText("14.044")).toBeInTheDocument();
    expect(screen.getByText(/seit 0:00 Uhr/)).toBeInTheDocument();
    expect(screen.getAllByText(/Datenstand/).length).toBeGreaterThan(0);
    expect(screen.getByText("42 Minuten")).toBeInTheDocument();
    expect(screen.getByText(/Baseline im Aufbau für 12 Benutzer/)).toBeInTheDocument();
    expect(screen.getByText(/1 Lauf fehlgeschlagen/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "7 Tage" }));
    expect(screen.getByRole("button", { name: "7 Tage" })).toHaveAttribute("aria-pressed", "true");
    const open = screen.getByRole("list", { name: "Offene Fälle nach Priorität" });
    await userEvent.click(within(open).getAllByRole("link")[0]!);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/cases");
    });
    expect(router.state.location.search).toMatchObject({ priority: ["P1"] });
  });

  it("switches theme and language, opens the shortcut help, searches and logs out", async () => {
    mockApi();
    const { router } = renderApp("/");
    await screen.findByText("14.044");
    await userEvent.click(screen.getByRole("button", { name: "Helles Design" }));
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Dunkles Design" }));
    expect(document.documentElement.classList.contains("dark")).toBe(true);

    await userEvent.keyboard("?");
    expect(await screen.findByRole("dialog", { name: "Tastaturkürzel" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");

    await userEvent.click(screen.getByRole("button", { name: "Sprache wechseln" }));
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
    setLanguage("de");
    expect(await screen.findByRole("heading", { name: "Lagebild" })).toBeInTheDocument();

    const search = screen.getByRole("searchbox", { name: "Fälle durchsuchen" });
    await userEvent.type(search, "jonas{Enter}");
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ q: "jonas" });
    });

    await userEvent.click(screen.getByRole("button", { name: /Demo Senior Analyst/ }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Abmelden" }));
    expect(await screen.findByText("Demo-Zugänge")).toBeInTheDocument();
    expect(sessionStorage.getItem("sentinelops.demoUser")).toBeNull();
    expect(i18n.language).toBe("de");
  });

  it("returns to the login page when the session expires", async () => {
    mockApi({ "GET /api/v1/dashboard": apiError(401, "token expired") });
    renderApp("/");
    expect(await screen.findByText("Demo-Zugänge")).toBeInTheDocument();
  });

  it("shows errors with a retry button and a not-found page", async () => {
    mockApi({ "GET /api/v1/dashboard": apiError(500, "boom") });
    renderApp("/");
    expect(await screen.findByRole("alert")).toHaveTextContent("500: boom");
    expect(screen.getByRole("button", { name: "Erneut versuchen" })).toBeInTheDocument();
  });

  it("renders the not-found page and forbidden errors", async () => {
    mockApi({ "GET /api/v1/rules": apiError(403, "missing permission") });
    renderApp("/does-not-exist");
    expect(await screen.findByText("Seite nicht gefunden")).toBeInTheDocument();
  });
});
