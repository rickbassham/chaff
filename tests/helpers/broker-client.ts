import { createConnection } from 'node:net';

/**
 * Send one newline-delimited JSON request to a broker socket and resolve with
 * the parsed newline-delimited JSON response. Shared by broker and launcher
 * tests so each does not re-implement the wire protocol.
 */
export function request(sockPath: string, req: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const conn = createConnection(sockPath);
    let buf = '';
    conn.on('error', reject);
    conn.on('connect', () => {
      conn.write(JSON.stringify(req) + '\n');
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        const line = buf.slice(0, nl);
        conn.end();
        try {
          resolve(JSON.parse(line));
        } catch (err) {
          reject(err as Error);
        }
      }
    });
  });
}
