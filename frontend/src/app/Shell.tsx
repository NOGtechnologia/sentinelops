import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  BookOpenCheck,
  Database,
  FileClock,
  FolderKanban,
  Keyboard,
  LayoutDashboard,
  LogOut,
  Moon,
  Network,
  ScrollText,
  Search,
  Settings,
  Sun,
  UserRound,
} from "lucide-react";
import { useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { useVersion } from "../api/hooks";
import { useAuth } from "../auth/AuthProvider";
import { Dialog } from "../components/Dialog";
import { Logo } from "../components/Logo";
import { Time } from "../components/Time";
import { setLanguage } from "../i18n";
import { cn } from "../lib/cn";
import { useHotkeys } from "../lib/hotkeys";
import { useTheme } from "./theme";

interface NavItem {
  to: string;
  label: string;
  icon: typeof Activity;
  permission: string;
}

export function Shell() {
  const { t, i18n } = useTranslation();
  const { me, can, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const version = useVersion();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [help, setHelp] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useHotkeys({
    "/": () => searchRef.current?.focus(),
    "?": () => {
      setHelp(true);
    },
    g: () => void navigate({ to: "/" }),
  });

  const nav: NavItem[] = [
    { to: "/", label: t("nav.dashboard"), icon: LayoutDashboard, permission: "dashboard:read" },
    { to: "/cases", label: t("nav.cases"), icon: FolderKanban, permission: "cases:read" },
    { to: "/entities", label: t("nav.entities"), icon: Network, permission: "entities:read" },
    { to: "/events", label: t("nav.events"), icon: ScrollText, permission: "events:read" },
    { to: "/rules", label: t("nav.rules"), icon: BookOpenCheck, permission: "rules:read" },
    { to: "/quality", label: t("nav.quality"), icon: Database, permission: "quality:read" },
    { to: "/audit", label: t("nav.audit"), icon: FileClock, permission: "audit:read" },
    { to: "/admin", label: t("nav.admin"), icon: Settings, permission: "admin:manage" },
  ];

  const isActive = (to: string) => (to === "/" ? pathname === "/" : pathname.startsWith(to));

  return (
    <div className="flex min-h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 btn">
        {t("common.skipToContent")}
      </a>
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-surface md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <Logo className="size-7" />
          <span className="text-base font-bold tracking-tight">{t("app.name")}</span>
        </div>
        <nav aria-label={t("nav.main")} className="flex flex-1 flex-col gap-0.5 px-2">
          {nav
            .filter((item) => can(item.permission))
            .map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-muted hover:bg-surface-2 hover:text-text",
                  isActive(item.to) &&
                    "bg-accent-soft font-semibold text-accent hover:bg-accent-soft hover:text-accent",
                )}
                aria-current={isActive(item.to) ? "page" : undefined}
              >
                <item.icon aria-hidden className="size-4" />
                {item.label}
              </Link>
            ))}
        </nav>
        <div className="border-t border-border px-4 py-3 text-xs text-muted">
          {version.data?.demo_mode && (
            <p className="mb-1 font-semibold text-warn">
              {t("app.demoMode")} · <Time value={version.data.demo_now} />
            </p>
          )}
          <p>
            {t("app.name")} {version.data?.version}
          </p>
          <p className="mt-1">{t("app.complements")}</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-border bg-surface/95 px-4 py-2 backdrop-blur">
          <form
            role="search"
            className="relative max-w-md flex-1"
            onSubmit={(event) => {
              event.preventDefault();
              const q = searchRef.current?.value.trim() ?? "";
              void navigate({ to: "/cases", search: q ? { q } : {} });
            }}
          >
            <Search aria-hidden className="pointer-events-none absolute top-2 left-2.5 size-4 text-muted" />
            <input
              ref={searchRef}
              type="search"
              className="input pl-8"
              placeholder={t("header.searchPlaceholder")}
              aria-label={t("header.search")}
            />
          </form>
          <div className="ml-auto flex items-center gap-1">
            <button
              type="button"
              className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-text"
              onClick={() => {
                setHelp(true);
              }}
              aria-label={t("shortcuts.title")}
              title={t("shortcuts.title")}
            >
              <Keyboard aria-hidden className="size-4" />
            </button>
            <button
              type="button"
              className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-text"
              onClick={() => {
                setTheme(theme === "dark" ? "light" : "dark");
              }}
              aria-label={theme === "dark" ? t("header.lightMode") : t("header.darkMode")}
              title={theme === "dark" ? t("header.lightMode") : t("header.darkMode")}
            >
              {theme === "dark" ? <Sun aria-hidden className="size-4" /> : <Moon aria-hidden className="size-4" />}
            </button>
            <button
              type="button"
              className="rounded-md px-2 py-1.5 text-xs font-semibold text-muted hover:bg-surface-2 hover:text-text"
              onClick={() => {
                setLanguage(i18n.language === "de" ? "en" : "de");
              }}
              aria-label={t("header.language")}
            >
              {i18n.language === "de" ? "EN" : "DE"}
            </button>
            <Dropdown.Root>
              <Dropdown.Trigger className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-surface-2">
                <UserRound aria-hidden className="size-4 text-muted" />
                <span className="hidden sm:inline">{me?.display_name}</span>
              </Dropdown.Trigger>
              <Dropdown.Portal>
                <Dropdown.Content
                  align="end"
                  sideOffset={6}
                  className="z-50 min-w-56 rounded-lg border border-border bg-surface p-1 shadow-xl"
                >
                  <div className="px-3 py-2 text-xs text-muted">
                    <p className="font-semibold text-text">{me?.username}</p>
                    <p>{me?.roles.map((r) => t(`roles.${r}`)).join(", ")}</p>
                  </div>
                  <Dropdown.Separator className="my-1 h-px bg-border" />
                  <Dropdown.Item
                    onSelect={logout}
                    className="flex cursor-pointer items-center gap-2 rounded px-3 py-2 text-sm outline-none data-[highlighted]:bg-surface-2"
                  >
                    <LogOut aria-hidden className="size-4" />
                    {t("auth.logout")}
                  </Dropdown.Item>
                </Dropdown.Content>
              </Dropdown.Portal>
            </Dropdown.Root>
          </div>
        </header>
        <MobileNav items={nav.filter((item) => can(item.permission))} isActive={isActive} />
        <main id="main" className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-5 lg:px-6">
          <Outlet />
        </main>
      </div>
      <HelpDialog open={help} onOpenChange={setHelp} />
    </div>
  );
}

function MobileNav({ items, isActive }: { items: NavItem[]; isActive: (to: string) => boolean }) {
  const { t } = useTranslation();
  return (
    <nav aria-label={t("nav.main")} className="flex gap-1 overflow-x-auto border-b border-border px-2 py-1 md:hidden">
      {items.map((item) => (
        <Link
          key={item.to}
          to={item.to}
          className={cn(
            "rounded px-2 py-1 text-xs whitespace-nowrap",
            isActive(item.to) ? "bg-accent-soft text-accent" : "text-muted",
          )}
        >
          {item.label}
        </Link>
      ))}
    </nav>
  );
}

function HelpDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const rows: [string, ReactNode][] = [
    ["j / k", t("shortcuts.nextPrev")],
    ["Enter", t("shortcuts.open")],
    ["a", t("shortcuts.assign")],
    ["x", t("shortcuts.select")],
    ["/", t("shortcuts.search")],
    ["g", t("shortcuts.dashboard")],
    ["1 – 5", t("shortcuts.tabs")],
    ["?", t("shortcuts.help")],
  ];
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("shortcuts.title")}>
      <table className="table">
        <tbody>
          {rows.map(([key, label]) => (
            <tr key={key}>
              <td className="w-24">
                <kbd className="kbd">{key}</kbd>
              </td>
              <td>{label}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Dialog>
  );
}
