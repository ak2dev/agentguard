import http from "node:http";

// OAuth redirect callback: wait for the authorization server to send the user back.
export function waitForCode(port: number, expectedState: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", `http://localhost:${port}`);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (state !== expectedState || !code) {
        res.end("Authorization failed.");
        reject(new Error("bad state"));
        return;
      }
      res.end("You can close this window.");
      server.close();
      resolve(code);
    });
    server.listen(port);
  });
}
