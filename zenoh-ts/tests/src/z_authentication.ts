//
// Copyright (c) 2026 Semio
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
/// <reference lib="deno.ns" />

// The remote-api plugin with `authentication`, in a bridge this test starts: a TLS listener
// that requires client certificates, and access control that lets `u:alice` put and subscribe
// on `demo/alice` only, and `u:observer` on `demo/**`. The certificates come from `openssl`,
// the ticket key and the tickets from WebCrypto.

import { Config, Sample, Session } from "@eclipse-zenoh/zenoh-ts";
import { assert } from "https://deno.land/std@0.192.0/testing/asserts.ts";

const ISSUER = "semio-studio";
const AUDIENCE = "semio-bridge";
const PATIENCE_MS = 10000;

const BRIDGE = new URL(
  `../../../target/release/zenoh-bridge-remote-api${Deno.build.os === "windows" ? ".exe" : ""}`,
  import.meta.url,
);

const OPENSSL_EXTENSIONS = `
[req]
distinguished_name = dn
[dn]
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[intermediate]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[router]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1, DNS:localhost
`;

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freePort(): number {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  listener.close();
  return port;
}

async function run(command: string, args: string[], cwd: string) {
  const output = await new Deno.Command(command, { args, cwd, stdout: "null", stderr: "piped" }).output();
  if (!output.success) {
    throw new Error(`${command} ${args.join(" ")}: ${new TextDecoder().decode(output.stderr)}`);
  }
}

/// A root CA, an intermediate CA under it that signs the client certificates, and the
/// router's certificate under the root, as PEM files in `dir`. Private keys are PKCS#8, and
/// signatures SHA-256: LibreSSL signs with SHA-1 by default, which rustls refuses.
async function writePki(dir: string) {
  await Deno.writeTextFile(`${dir}/openssl.cnf`, OPENSSL_EXTENSIONS);
  const key = async (name: string) => {
    await run("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", `${name}.sec1`], dir);
    await run("openssl", ["pkcs8", "-topk8", "-nocrypt", "-in", `${name}.sec1`, "-out", `${name}.key`], dir);
  };
  const signed = async (name: string, subject: string, extensions: string, serial: string) => {
    await key(name);
    await run("openssl", [
      "req", "-new", "-sha256", "-config", "openssl.cnf", "-key", `${name}.key`, "-subj", subject, "-out", `${name}.csr`,
    ], dir);
    await run("openssl", [
      "x509", "-req", "-sha256", "-in", `${name}.csr`, "-CA", "root.pem", "-CAkey", "root.key", "-set_serial", serial,
      "-days", "1", "-extfile", "openssl.cnf", "-extensions", extensions, "-out", `${name}.pem`,
    ], dir);
  };
  await key("root");
  await run("openssl", [
    "req", "-new", "-x509", "-sha256", "-config", "openssl.cnf", "-extensions", "root", "-key", "root.key",
    "-subj", "/CN=Test Root CA", "-days", "1", "-out", "root.pem",
  ], dir);
  await signed("gateway-ca", "/CN=Test Gateway CA", "intermediate", "2");
  await signed("router", "/CN=test-router", "router", "3");
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pem(label: string, der: Uint8Array): string {
  const body = btoa(String.fromCharCode(...der)).match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/// Signs tickets: compact ES256 JWTs.
class TicketIssuer {
  private constructor(private keys: CryptoKeyPair) {}

  static async generate(): Promise<TicketIssuer> {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    return new TicketIssuer(keys);
  }

  async publicKeyPem(): Promise<string> {
    return pem("PUBLIC KEY", new Uint8Array(await crypto.subtle.exportKey("spki", this.keys.publicKey)));
  }

  async ticket(sub: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const encode = (value: object) => base64Url(new TextEncoder().encode(JSON.stringify(value)));
    const signed = `${encode({ alg: "ES256", typ: "JWT" })}.${encode({
      iss: ISSUER, aud: AUDIENCE, sub, iat: now, exp: now + 300, jti: crypto.randomUUID(),
    })}`;
    // WebCrypto's ECDSA signature is r || s, which is what JWS uses.
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, this.keys.privateKey, new TextEncoder().encode(signed),
    );
    return `${signed}.${base64Url(new Uint8Array(signature))}`;
  }
}

/// The bridge, with its logs kept for when a test fails.
class Bridge {
  private log = "";
  private drained: Promise<void>;

  private constructor(private child: Deno.ChildProcess, readonly wsPort: number) {
    this.drained = (async () => {
      for await (const chunk of child.stderr.pipeThrough(new TextDecoderStream())) {
        this.log += chunk;
      }
    })();
  }

  static async start(dir: string, tickets: TicketIssuer): Promise<Bridge> {
    const [tlsPort, wsPort] = [freePort(), freePort()];
    const rule = (id: string, keys: string[]) => ({
      id, messages: ["put", "delete", "declare_subscriber"], flows: ["ingress", "egress"],
      permission: "allow", key_exprs: keys,
    });
    const config = {
      listen: { endpoints: [`tls/127.0.0.1:${tlsPort}`] },
      scouting: { multicast: { enabled: false }, gossip: { enabled: false } },
      transport: {
        link: {
          tls: {
            root_ca_certificate: `${dir}/root.pem`,
            listen_certificate: `${dir}/router.pem`,
            listen_private_key: `${dir}/router.key`,
            enable_mtls: true,
          },
        },
      },
      access_control: {
        enabled: true,
        default_permission: "deny",
        rules: [rule("alice", ["demo/alice"]), rule("observer", ["demo/**"])],
        subjects: [
          { id: "alice", cert_common_names: ["u:alice"] },
          { id: "observer", cert_common_names: ["u:observer"] },
        ],
        policies: [
          { rules: ["alice"], subjects: ["alice"] },
          { rules: ["observer"], subjects: ["observer"] },
        ],
      },
      plugins: {
        remote_api: {
          websocket_port: `127.0.0.1:${wsPort}`,
          authentication: {
            ticket: {
              public_keys: [await tickets.publicKeyPem()],
              issuer: ISSUER,
              audience: AUDIENCE,
              principal_prefix: "u:",
            },
            client_session: {
              connect: `tls/127.0.0.1:${tlsPort}`,
              root_ca_certificate: `${dir}/root.pem`,
              signing_certificate: `${dir}/gateway-ca.pem`,
              signing_private_key: `${dir}/gateway-ca.key`,
            },
          },
        },
      },
    };
    await Deno.writeTextFile(`${dir}/bridge.json5`, JSON.stringify(config));
    const child = new Deno.Command(BRIDGE, {
      args: ["-c", `${dir}/bridge.json5`, "--no-multicast-scouting"],
      env: { RUST_LOG: "warn" },
      stdout: "null",
      stderr: "piped",
    }).spawn();
    const bridge = new Bridge(child, wsPort);

    const deadline = Date.now() + PATIENCE_MS;
    for (;;) {
      try {
        (await Deno.connect({ hostname: "127.0.0.1", port: wsPort })).close();
        return bridge;
      } catch {
        if (Date.now() > deadline) {
          await bridge.stop();
          throw new Error(`the bridge never listened on ${wsPort}:\n${bridge.log}`);
        }
        await sleep(100);
      }
    }
  }

  url(ticket?: string): string {
    return ticket === undefined ? `ws://127.0.0.1:${this.wsPort}/` : `ws://127.0.0.1:${this.wsPort}/?ticket=${ticket}`;
  }

  async stop(): Promise<string> {
    this.child.kill("SIGTERM");
    await this.child.status;
    await this.drained;
    return this.log;
  }
}

/// `Session.open`, failing after `PATIENCE_MS`: when the WebSocket closes as soon as it
/// opens, zenoh-ts retries for half an hour.
async function openSession(url: string): Promise<Session> {
  let timer: number | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`no session through ${url.split("?")[0]}`)), PATIENCE_MS);
  });
  try {
    return await Promise.race([Session.open(new Config(url, 5000)), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/// Whether a plain WebSocket to `url` opens; `false` once the upgrade is refused.
function webSocketOpens(url: string): Promise<boolean> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url);
    ws.onopen = () => {
      ws.onclose = () => resolve(true);
      ws.close();
    };
    ws.onerror = () => {};
    ws.onclose = () => resolve(false);
  });
}

type Received = { key: string; payload: string };

async function subscribe(session: Session, keys: string[]): Promise<Received[]> {
  const received: Received[] = [];
  for (const key of keys) {
    await session.declareSubscriber(key, {
      handler: (sample: Sample) => {
        received.push({ key: sample.keyexpr().toString(), payload: sample.payload().toString() });
      },
    });
  }
  return received;
}

function has(received: Received[], key: string, payload: string): boolean {
  return received.some((r) => r.key === key && r.payload === payload);
}

Deno.test("Authentication - tickets admit principals, and the router's access control applies to them", async () => {
  const dir = await Deno.makeTempDir({ prefix: "zenoh-ts-authentication-" });
  let bridge: Bridge | undefined;
  let alice: Session | undefined;
  let observer: Session | undefined;
  let passed = false;
  try {
    await writePki(dir);
    const tickets = await TicketIssuer.generate();
    bridge = await Bridge.start(dir, tickets);

    // The upgrade is refused without a ticket, or with one the bridge does not trust.
    assert(!(await webSocketOpens(bridge.url())), "opened without a ticket");
    const stranger = await TicketIssuer.generate();
    assert(!(await webSocketOpens(bridge.url(await stranger.ticket("alice")))), "opened with an untrusted ticket");

    // A ticket admits its principal. The URL form keeps the query; `ws/host:port` would drop it.
    alice = await openSession(bridge.url(await tickets.ticket("alice")));
    observer = await openSession(bridge.url(await tickets.ticket("observer")));

    const aliceReceived = await subscribe(alice, ["demo/alice", "demo/bob"]);
    const observerReceived = await subscribe(observer, ["demo/alice", "demo/bob"]);

    const deadline = Date.now() + PATIENCE_MS;
    while (!(has(observerReceived, "demo/alice", "from alice") && has(aliceReceived, "demo/alice", "from observer"))) {
      assert(Date.now() < deadline, "the allowed exchange never happened");
      await alice.put("demo/alice", "from alice");
      await alice.put("demo/bob", "from alice");
      await observer.put("demo/alice", "from observer");
      await observer.put("demo/bob", "from observer");
      await sleep(200);
    }
    // Give anything denied the same time again to show up.
    await sleep(500);

    assert(!has(observerReceived, "demo/bob", "from alice"), "a denied put went through");
    assert(!has(aliceReceived, "demo/bob", "from observer"), "a denied subscription received");
    passed = true;
  } finally {
    await alice?.close();
    await observer?.close();
    const log = await bridge?.stop();
    if (!passed && log) {
      console.error(`bridge log:\n${log}`);
    }
    await Deno.remove(dir, { recursive: true });
  }
});
