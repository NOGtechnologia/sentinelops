import type { paths } from "./schema";

/** A path that exists in the OpenAPI document - typos are compile errors. */
export type ApiPath = keyof paths;

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

type Query = Record<string, string | number | boolean | string[] | null | undefined>;

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  path?: Record<string, string>;
  query?: Query;
  body?: unknown;
  form?: FormData;
  signal?: AbortSignal;
}

// The access token lives in memory only (never in web storage, spec 16.1 / ASVS V3).
let accessToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

export function buildUrl(path: ApiPath, params?: Record<string, string>, query?: Query): string {
  const url = (path as string).replace(/\{(\w+)\}/g, (_, name: string) => {
    const value = params?.[name];
    if (value === undefined) throw new Error(`missing path parameter ${name}`);
    return encodeURIComponent(value);
  });
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value))
      value.forEach((v) => {
        search.append(key, v);
      });
    else search.append(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${url}?${qs}` : url;
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const data = (await response.json()) as { detail?: unknown };
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) return data.detail.map((d: { msg?: string }) => d.msg ?? "").join("; ");
  } catch {
    // not JSON
  }
  return response.statusText || "request failed";
}

export async function request(path: ApiPath, options: RequestOptions = {}): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let body: BodyInit | undefined;
  if (options.form) {
    body = options.form;
  } else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  const response = await fetch(buildUrl(path, options.path, options.query), {
    method: options.method ?? "GET",
    headers,
    ...(body === undefined ? {} : { body }),
    ...(options.signal ? { signal: options.signal } : {}),
    credentials: "same-origin",
  });
  if (!response.ok) {
    if (response.status === 401 && onUnauthorized) onUnauthorized();
    throw new ApiError(response.status, await errorDetail(response));
  }
  return response;
}

export async function api<T>(path: ApiPath, options: RequestOptions = {}): Promise<T> {
  const response = await request(path, options);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Download a binary/text export and hand it to the browser as a file. */
export async function download(path: ApiPath, options: RequestOptions, fallbackName: string): Promise<void> {
  const response = await request(path, options);
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = /filename="([^"]+)"/.exec(disposition);
  const name = match?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
