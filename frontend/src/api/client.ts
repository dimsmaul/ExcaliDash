import axios from "axios";

export const API_URL = (import.meta.env.VITE_API_URL || "/api").replace(
  /\/+$/,
  "",
);

/**
 * Stored references (file URLs, preview image hrefs) are saved as `/api/...`.
 * Map them onto the configured API base so the frontend also works when the API
 * lives on another host (`VITE_API_URL=https://api.example.com`); with the default
 * `/api` the path is unchanged.
 */
export const toApiUrl = (path: string): string =>
  path.startsWith("/api/") ? `${API_URL}${path.slice("/api".length)}` : path;

/** `toApiUrl` for every `"/api/files/…"` reference inside a preview SVG. */
export const withApiFileUrls = (svg: string): string =>
  API_URL === "/api" ? svg : svg.split('"/api/files/').join(`"${API_URL}/files/`);

export const api = axios.create({
  baseURL: API_URL,
  withCredentials: true,
});

export { default as axios } from "axios";
export const isAxiosError = axios.isAxiosError;
