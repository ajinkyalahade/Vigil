const API_BASE_KEY = "sc_api_base";
const API_TOKEN_KEY = "sc_api_token";

export function getApiBase(): string {
  const fromStorage = localStorage.getItem(API_BASE_KEY);
  if (fromStorage && fromStorage.trim()) return fromStorage.trim();
  const fromEnv = import.meta.env.VITE_API_BASE as string | undefined;
  return (fromEnv && fromEnv.trim()) || "http://127.0.0.1:8000";
}

export function setApiBase(value: string): void {
  localStorage.setItem(API_BASE_KEY, value);
}

export function getApiToken(): string | null {
  const value = localStorage.getItem(API_TOKEN_KEY);
  return value && value.trim() ? value.trim() : null;
}

export function setApiToken(value: string): void {
  localStorage.setItem(API_TOKEN_KEY, value);
}

