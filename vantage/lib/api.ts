// Same-origin calls to the TripWire backend. The server refuses any POST without this header.
const CLIENT_HEADERS = { "Content-Type": "application/json", "X-TripWire-Client": "dashboard" };

async function read<T>(response: Response): Promise<T> {
  let data: { error?: string } = {};
  try {
    data = await response.json();
  } catch {
    throw new Error("server returned " + response.status);
  }
  if (!response.ok) throw new Error(data.error || "HTTP " + response.status);
  return data as T;
}

export async function apiGet<T>(path: string): Promise<T> {
  return read<T>(await fetch(path));
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  return read<T>(await fetch(path, { method: "POST", headers: CLIENT_HEADERS, body: JSON.stringify(body) }));
}
