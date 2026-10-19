import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

export type Theme = "dark" | "light";
const THEME_KEY = "sentinelops.theme";

function initialTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(THEME_KEY);
    if (stored === "dark" || stored === "light") return stored;
  } catch {
    // ignore
  }
  return "dark"; // analyst workstations: dark by default (spec 17.1)
}

function apply(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

const ThemeContext = createContext<{ theme: Theme; setTheme: (theme: Theme) => void }>({
  theme: "dark",
  setTheme: () => undefined,
});

export function ThemeProvider({ children, forced }: { children: ReactNode; forced?: Theme | undefined }) {
  const [theme, setState] = useState<Theme>(() => {
    const value = forced ?? initialTheme();
    apply(value);
    return value;
  });
  const setTheme = useCallback((value: Theme) => {
    apply(value);
    setState(value);
    try {
      // eslint-disable-next-line no-restricted-syntax -- UI theme preference only, no token or log data
      window.localStorage.setItem(THEME_KEY, value);
    } catch {
      // ignore
    }
  }, []);
  const value = useMemo(() => ({ theme, setTheme }), [theme, setTheme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}
