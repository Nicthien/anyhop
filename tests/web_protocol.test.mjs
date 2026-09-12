// note: the "node:assert" root import (not the /strict subpath) is what
// static analyzers recognize as an assertion library — same strict API.
import { strict as assert } from "node:assert";
import test from "node:test";

import {
  enabledChannelKeys,
  parseSpeedStream,
  visibleTraffic,
  writeClipboard,
} from "../src/anyhop/assets/dashboard.js";

function stream(parts) {
  return new ReadableStream({
    start(controller) {
      for (const part of parts) controller.enqueue(part);
      controller.close();
    },
  });
}

const enc = new TextEncoder();

test("clipboard uses the secure-context API when available", async () => {
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  let copied = "";
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { clipboard: { writeText: async (text) => { copied = text; } } },
  });
  try {
    await writeClipboard("router-address");
    assert.equal(copied, "router-address");
  } finally {
    if (previousNavigator) Object.defineProperty(globalThis, "navigator", previousNavigator);
    else delete globalThis.navigator;
  }
});

test("clipboard falls back to selection copy on insecure LAN origins", async () => {
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const input = {
    style: {},
    setAttribute() {},
    select() { this.selected = true; },
    setSelectionRange(start, end) { this.range = [start, end]; },
    remove() { this.removed = true; },
  };
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: {} });
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      body: { appendChild(node) { node.appended = true; } },
      createElement: () => input,
      execCommand(command) { return command === "copy"; },
    },
  });
  try {
    await writeClipboard("proxy-address");
    assert.equal(input.value, "proxy-address");
    assert.equal(input.appended, true);
    assert.equal(input.selected, true);
    assert.deepEqual(input.range, [0, 13]);
    assert.equal(input.removed, true);
  } finally {
    if (previousNavigator) Object.defineProperty(globalThis, "navigator", previousNavigator);
    else delete globalThis.navigator;
    if (previousDocument) Object.defineProperty(globalThis, "document", previousDocument);
    else delete globalThis.document;
  }
});

test("disabled channels expose no test targets or cached traffic", () => {
  const channels = [
    { provider: "nordvpn", name: "us_1", enabled: false },
    { provider: "protonvpn", name: "us_1", enabled: false },
  ];
  assert.deepEqual(enabledChannelKeys(channels), []);
  assert.deepEqual(visibleTraffic(channels[0], { sent: 1024, received: 2048 }), {
    sent: "",
    received: "",
  });
});

test("batch test targets and traffic include enabled channels only", () => {
  const disabled = { provider: "nordvpn", name: "us_1", enabled: false };
  const enabled = { provider: "protonvpn", name: "us_1", enabled: true };
  assert.deepEqual(enabledChannelKeys([disabled, enabled]), ["protonvpn/us_1"]);
  assert.deepEqual(visibleTraffic(enabled, { sent: 1024, received: 2048 }), {
    sent: "1.0 KB",
    received: "2.0 KB",
  });
});

test("speed NDJSON decodes split UTF-8 and a final non-newline terminal", async () => {
  const text = '{"type":"row","data":{"provider":"nordvpn","name":"東京"}}\n'
    + '{"type":"done","data":{"channel_count":1}}';
  const bytes = enc.encode(text);
  const rows = [];
  const terminal = await parseSpeedStream(
    stream([bytes.slice(0, 49), bytes.slice(49, 54), bytes.slice(54)]),
    (row) => rows.push(row),
  );
  assert.equal(rows[0].name, "東京");
  assert.equal(terminal.type, "done");
});

for (const [name, records, pattern] of [
  ["missing terminal", ['{"type":"row","data":{}}\n'], /without a terminal/],
  ["malformed record", ["{nope}\n"], /malformed/],
  ["unknown record", ['{"type":"wat","data":{}}\n'], /unknown/],
  ["duplicate terminal", ['{"type":"done","data":{}}\n{"type":"done","data":{}}\n'], /after terminal/],
  ["row after terminal", ['{"type":"done","data":{}}\n{"type":"row","data":{}}\n'], /after terminal/],
]) {
  test(`speed NDJSON rejects ${name}`, async () => {
    await assert.rejects(parseSpeedStream(stream(records.map((x) => enc.encode(x)))), pattern);
  });
}
