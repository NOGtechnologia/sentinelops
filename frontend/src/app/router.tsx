import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import type { EventFilters } from "../api/hooks";
import { useAuth } from "../auth/AuthProvider";
import { Empty, Loading } from "../components/States";
import { AdminPage } from "../pages/AdminPage";
import { AuditPage } from "../pages/AuditPage";
import { CaseLayout } from "../pages/case/CaseLayout";
import { EvidenceTab } from "../pages/case/EvidenceTab";
import { GraphTab } from "../pages/case/GraphTab";
import { OverviewTab } from "../pages/case/OverviewTab";
import { ReportTab } from "../pages/case/ReportTab";
import { TimelineTab } from "../pages/case/TimelineTab";
import { CaseQueuePage, type QueueSearch } from "../pages/CaseQueuePage";
import { DashboardPage } from "../pages/DashboardPage";
import { EntitiesPage } from "../pages/EntitiesPage";
import { EventsPage } from "../pages/EventsPage";
import { LoginPage } from "../pages/LoginPage";
import { QualityPage } from "../pages/QualityPage";
import { RuleDetailPage } from "../pages/RuleDetailPage";
import { RulesPage } from "../pages/RulesPage";
import { Shell } from "./Shell";

function Root() {
  const { status } = useAuth();
  if (status === "loading") return <Loading />;
  if (status === "anonymous") return <LoginPage />;
  return <Shell />;
}

function NotFound() {
  const { t } = useTranslation();
  return <Empty title={t("errors.pageNotFound")} />;
}

const list = (value: unknown): string[] | undefined => {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  if (typeof value === "string" && value) return value.split(",");
  return undefined;
};
const text = (value: unknown): string | undefined => (typeof value === "string" && value ? value : undefined);

const rootRoute = createRootRoute({ component: Root, notFoundComponent: NotFound });

const dashboardRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: DashboardPage });

const casesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/cases",
  component: CaseQueuePage,
  validateSearch: (search: Record<string, unknown>): QueueSearch => ({
    status: list(search.status),
    priority: list(search.priority),
    q: text(search.q),
    entity: text(search.entity),
  }),
});

const caseRoute = createRoute({ getParentRoute: () => rootRoute, path: "/cases/$caseId", component: CaseLayout });
const caseOverviewRoute = createRoute({ getParentRoute: () => caseRoute, path: "/", component: OverviewTab });
const caseTimelineRoute = createRoute({ getParentRoute: () => caseRoute, path: "/timeline", component: TimelineTab });
const caseEvidenceRoute = createRoute({ getParentRoute: () => caseRoute, path: "/evidence", component: EvidenceTab });
const caseGraphRoute = createRoute({ getParentRoute: () => caseRoute, path: "/graph", component: GraphTab });
const caseReportRoute = createRoute({ getParentRoute: () => caseRoute, path: "/report", component: ReportTab });

const rulesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/rules", component: RulesPage });
const ruleRoute = createRoute({ getParentRoute: () => rootRoute, path: "/rules/$ruleId", component: RuleDetailPage });
const qualityRoute = createRoute({ getParentRoute: () => rootRoute, path: "/quality", component: QualityPage });
const entitiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/entities",
  component: EntitiesPage,
  validateSearch: (search: Record<string, unknown>): { type?: string | undefined; q?: string | undefined } => ({
    type: text(search.type),
    q: text(search.q),
  }),
});
const eventsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/events",
  component: EventsPage,
  validateSearch: (search: Record<string, unknown>): EventFilters => ({
    q: text(search.q),
    user: text(search.user),
    host: text(search.host),
    ip: text(search.ip),
    action: text(search.action),
    start: text(search.start),
    end: text(search.end),
    assessment: text(search.assessment),
  }),
});
const auditRoute = createRoute({ getParentRoute: () => rootRoute, path: "/audit", component: AuditPage });
const adminRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin", component: AdminPage });
const callbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/auth/callback",
  component: () => <Outlet />,
});

export const routeTree = rootRoute.addChildren([
  dashboardRoute,
  casesRoute,
  caseRoute.addChildren([caseOverviewRoute, caseTimelineRoute, caseEvidenceRoute, caseGraphRoute, caseReportRoute]),
  rulesRoute,
  ruleRoute,
  qualityRoute,
  entitiesRoute,
  eventsRoute,
  auditRoute,
  adminRoute,
  callbackRoute,
]);

export function makeRouter(history?: Parameters<typeof createRouter>[0]["history"]) {
  return createRouter({ routeTree, defaultPreload: false, scrollRestoration: true, ...(history ? { history } : {}) });
}

export const router = makeRouter();

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
