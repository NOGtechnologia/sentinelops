import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { secondCase } from "./fixtures";
import { mockApi, renderApp } from "./harness";

describe("case queue", () => {
  it("lists cases with priority symbol and text, entities as text and filters", async () => {
    const { calls } = mockApi();
    const { router } = renderApp("/cases?priority=P1&status=new");
    const table = await screen.findByRole("table", { name: "Fall-Warteschlange" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    const first = rows[1]!;
    expect(within(first).getByText("P1")).toBeInTheDocument();
    expect(within(first).getByText("kritisch")).toBeInTheDocument();
    expect(first.querySelector("[data-priority='P1'] svg")).not.toBeNull();
    expect(within(first).getByText("Prompt-Injection-Hinweis")).toBeInTheDocument();
    expect(within(first).getByText("Bezug zu 1 Fall")).toBeInTheDocument();
    expect(within(first).getByText("+2")).toBeInTheDocument(); // entities beyond the first three
    expect(within(first).getByText("+1")).toBeInTheDocument(); // rules beyond the first three
    expect(document.querySelector("img")).toBeNull(); // log values are text, never markup
    const request = calls.find((c) => c.path === "/api/v1/cases");
    expect(request?.query.getAll("priority")).toEqual(["P1"]);

    await userEvent.click(screen.getByRole("button", { name: "Neu" }));
    await waitFor(() => {
      expect(router.state.location.search).not.toHaveProperty("status");
    });
    await userEvent.click(screen.getByRole("button", { name: /P2/ }));
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ priority: ["P1", "P2"] });
    });
    await userEvent.type(screen.getByLabelText("Suche"), "anna{Enter}");
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ q: "anna" });
    });
    await userEvent.click(screen.getByRole("button", { name: "Filter zurücksetzen" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({});
    });
  });

  it("supports keyboard navigation, selection and bulk actions", async () => {
    const { calls } = mockApi();
    const { router } = renderApp("/cases");
    await screen.findByRole("table", { name: "Fall-Warteschlange" });
    await userEvent.keyboard("j");
    await userEvent.keyboard("k");
    await userEvent.keyboard("x");
    expect(screen.getByText("1 ausgewählt")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox", { name: `Fall ${secondCase.case_id.slice(0, 8)} auswählen` }));
    expect(screen.getByText("2 ausgewählt")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "In Bearbeitung setzen" }));
    await userEvent.keyboard("a");
    await waitFor(() => {
      expect(calls.filter((c) => c.path === "/api/v1/cases/bulk")).toHaveLength(2);
    });
    const bulk = calls.filter((c) => c.path === "/api/v1/cases/bulk");
    expect(bulk[0]?.body).toMatchObject({ status: "in_progress" });
    expect(bulk[1]?.body).toMatchObject({ assignee: "demo.senior" });
    await userEvent.click(screen.getByRole("button", { name: "Auswahl aufheben" }));
    expect(screen.queryByText(/ausgewählt/)).not.toBeInTheDocument();
    await userEvent.keyboard("{Enter}");
    await waitFor(() => {
      // the checkbox click moved the cursor to the second row
      expect(router.state.location.pathname).toBe(`/cases/${secondCase.case_id}`);
    });
  });

  it("shows an empty state and the entity filter", async () => {
    mockApi({ "GET /api/v1/cases": { total: 0, offset: 0, limit: 200, items: [] } });
    renderApp("/cases?entity=dc01");
    expect(await screen.findByText("Keine Fälle für diese Filter")).toBeInTheDocument();
    expect(screen.getByText("dc01")).toBeInTheDocument();
  });
});
