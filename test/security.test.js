import { test } from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.EVM_ADDRESS ||= "0x1111111111111111111111111111111111111111";
process.env.FACILITATOR_URL ||= "https://x402.org/facilitator";
process.env.ENABLE_TEST_ENDPOINTS ||= "false";

const { assertSafeUrl, runTokenRiskScan } = await import("../dist/index.js");

test("rejects private IPv4 addresses", async () => {
  await assert.rejects(() => assertSafeUrl("http://127.0.0.1"), /not allowed/);
});

test("rejects localhost", async () => {
  await assert.rejects(() => assertSafeUrl("http://localhost"), /not allowed/);
});

test("returns a safe invalid-address result", async () => {
  const result = await runTokenRiskScan({ token: "not-an-address" });
  const value = JSON.parse(String(result.content[0].text));
  assert.equal(value.risk, "high");
  assert.equal(value.checks.formatValid, false);
});
