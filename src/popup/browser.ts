
export interface Settings {
  historyEnabled: boolean;
}

export interface TrustedKey {
  keyId: string;
  label: string;
  addedAt: string;
}

export interface HistoryEntry {
  origin: string;
  state: string;
  at: string;
}

export const DEFAULT_SETTINGS: Settings = { historyEnabled: false };

const hasChrome = (): boolean => typeof chrome !== 'undefined' && !!chrome.storage?.local;

const memory = new Map<string, unknown>();

async function get<T>(key: string, fallback: T): Promise<T> {
  try {
    if (!hasChrome()) return (memory.get(key) as T | undefined) ?? fallback;
    const r = await chrome.storage.local.get(key);
    return (r[key] as T | undefined) ?? fallback;
  } catch {
    return fallback;
  }
}
async function set(key: string, value: unknown): Promise<void> {
  try {
    if (!hasChrome()) memory.set(key, value);
    else await chrome.storage.local.set({ [key]: value });
  } catch {
    /* storage unavailable: the UI keeps working without persistence */
  }
}

export const loadSettings = async (): Promise<Settings> => ({ ...DEFAULT_SETTINGS, ...(await get<Partial<Settings>>('settings', {})) });
export const saveSettings = (s: Settings): Promise<void> => set('settings', s);
export const loadTrustedKeys = (): Promise<TrustedKey[]> => get<TrustedKey[]>('trustedKeys', []);
export const saveTrustedKeys = (k: TrustedKey[]): Promise<void> => set('trustedKeys', k);
export const loadHistory = (): Promise<HistoryEntry[]> => get<HistoryEntry[]>('history', []);
export const saveHistory = (h: HistoryEntry[]): Promise<void> => set('history', h.slice(0, 20));
export async function clearAll(): Promise<void> {
  memory.clear();
  try {
    if (hasChrome()) await chrome.storage.local.clear();
  } catch {
    /* ignore */
  }
}

export async function getActiveTabUrl(): Promise<string | null> {
  try {
    if (typeof chrome === 'undefined' || !chrome.tabs) return null;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url;
    return url && /^https?:\/\//i.test(url) ? url : null;
  } catch {
    return null;
  }
}

export const hostPatterns = (origin: string): string[] => {
  const host = new URL(origin).hostname;
  // Host access is declared in the manifest (host_permissions), so contains() is normally true and no prompt appears.
  // The request() fallback only fires if the user restricted site access in chrome://extensions.
  return [`http://${host}/*`, `https://${host}/*`];
};

export type AccessResult = 'already' | 'granted' | 'denied';

export async function ensureHostAccess(origin: string): Promise<AccessResult> {
  if (typeof chrome === 'undefined' || !chrome.permissions) return 'already'; // dev/test harness
  const origins = hostPatterns(origin);
  if (await chrome.permissions.contains({ origins })) return 'already';
  return (await chrome.permissions.request({ origins })) ? 'granted' : 'denied';
}
