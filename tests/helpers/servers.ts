import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Fixture {
  status?: number;
  headers?: Record<string, string | string[]>;
  redirectTo?: string;
  body?: string;
}

export interface TestServer {
  port: number;
  requests: { method: string; url: string; headers: Record<string, string | string[] | undefined> }[];
  close(): Promise<void>;
  setFixture(f: Fixture): void;
}

export async function startServer(initial: Fixture, port = 0): Promise<TestServer> {
  let fixture = initial;
  const requests: TestServer['requests'] = [];
  const server: Server = createServer((req, res) => {
    requests.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers });
    if (fixture.redirectTo) {
      res.writeHead(fixture.status ?? 302, { location: fixture.redirectTo });
      res.end();
      return;
    }
    res.writeHead(fixture.status ?? 200, { 'content-type': 'text/html', ...(fixture.headers ?? {}) });
    res.end(fixture.body ?? '<html><body>fixture</body></html>');
  });
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
  return {
    port: (server.address() as AddressInfo).port,
    requests,
    setFixture: (f) => {
      fixture = f;
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

export const originOf = (s: TestServer, host = '127.0.0.1'): string => `http://${host}:${s.port}`;
