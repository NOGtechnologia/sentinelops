import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import de from "./de.json";
import en from "./en.json";

export const LANGUAGES = ["de", "en"] as const;
export type Language = (typeof LANGUAGES)[number];

const LANGUAGE_KEY = "sentinelops.language";

function initialLanguage(): Language {
  try {
    const stored = window.localStorage.getItem(LANGUAGE_KEY);
    if (stored === "de" || stored === "en") return stored;
  } catch {
    // ignore
  }
  return "de";
}

void i18n.use(initReactI18next).init({
  resources: { de: { translation: de }, en: { translation: en } },
  lng: initialLanguage(),
  fallbackLng: "de",
  interpolation: { escapeValue: false }, // React escapes every text node itself
  returnNull: false,
});

export function setLanguage(language: Language): void {
  void i18n.changeLanguage(language);
  document.documentElement.lang = language;
  try {
    // eslint-disable-next-line no-restricted-syntax -- UI language preference only, no token or log data
    window.localStorage.setItem(LANGUAGE_KEY, language);
  } catch {
    // ignore
  }
}

export function locale(language: string): string {
  return language === "en" ? "en-GB" : "de-DE";
}

export default i18n;
