import js from "@eslint/js";
import i18next from "eslint-plugin-i18next";
import jsxA11y from "eslint-plugin-jsx-a11y";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "coverage", "src/api/schema.d.ts", ".api-check.d.ts", "scripts"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  jsxA11y.flatConfigs.strict,
  noUnsanitized.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: { "react-hooks": reactHooks, i18next },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-restricted-syntax": [
        "error",
        // Log data is hostile: never render HTML from strings (spec 12.4 / 16.1).
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Render log data as text only." },
        // Accessible names and hints are UI text too (spec 15.6).
        {
          selector:
            "JSXAttribute[name.name=/^(title|aria-label|placeholder|alt)$/] > Literal[value=/[A-Za-zÄÖÜäöüß]{2,}/]",
          message: "Use i18n for user-visible attribute text.",
        },
        // Tokens and data stay in memory (ASVS V3); UI preferences need a justified exception.
        {
          selector:
            "CallExpression[callee.property.name='setItem'][callee.object.name='localStorage'], CallExpression[callee.property.name='setItem'][callee.object.property.name='localStorage']",
          message: "Do not persist data in localStorage.",
        },
      ],
      // No hard-coded UI text: every visible JSX text goes through i18n (spec 15.6). Pure separators,
      // numbers and identifiers (P1, E12, rule ids) are not language.
      "i18next/no-literal-string": [
        "error",
        {
          mode: "jsx-text-only",
          words: {
            exclude: [/^[\s\d·–—→…:;,.()[\]{}|/=+*#&%$@!?<>"'`~^_-]*$/u, /^[A-Z0-9_-]+$/u, /^v$/u, /^SentinelOps$/u],
          },
        },
      ],
      // Scrollable regions and code blocks must be keyboard focusable (axe: scrollable-region-focusable).
      "jsx-a11y/no-noninteractive-tabindex": ["error", { tags: ["pre"], roles: ["tabpanel", "region"] }],
      // We do not use the React Compiler; the advisory about TanStack Virtual does not apply.
      "react-hooks/incompatible-library": "off",
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },
  {
    files: ["**/*.test.{ts,tsx}", "src/test/**"],
    rules: {
      "i18next/no-literal-string": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
  {
    files: ["*.config.{js,ts}", "eslint.config.js"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { globals: globals.node },
  },
);
