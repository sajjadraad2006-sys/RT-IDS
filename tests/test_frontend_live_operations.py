"""Behavioral tests for the bounded Live Operations polling controller."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("node") is None, reason="node is unavailable")
def test_live_operations_poller_guards_overlap_stale_hidden_and_duplicates():
    root = Path(__file__).resolve().parents[1]
    script = r"""
const assert = require('assert');
global.window = global;
global.CG = {};
require('./frontend/js/live-operations.js');

const listeners = {};
const documentRef = {
  hidden: false,
  addEventListener: (name, fn) => { listeners[name] = fn; },
  removeEventListener: () => {},
};
let calls = [];
let resolvers = [];
const fetchSnapshot = ({signal} = {}) => {
  calls.push(signal);
  return new Promise((resolve) => resolvers.push(resolve));
};
const applied = [];
const states = [];
const poller = new CG.LiveOperationsPoller({
  fetchSnapshot,
  applySnapshot: (value) => applied.push(value.sequence.uploaded_flow_records),
  onState: (value) => states.push(value),
  documentRef,
  setIntervalFn: () => 1,
  clearIntervalFn: () => {},
});

(async () => {
  const first = poller.refresh();
  const overlap = poller.refresh({supersede: false});
  assert.strictEqual(calls.length, 1, 'overlapping request was started');
  assert.strictEqual(overlap, first);

  const newer = poller.refresh({supersede: true});
  assert.strictEqual(calls.length, 2, 'manual refresh did not supersede');
  resolvers[1]({sequence: {uploaded_flow_records: 2}});
  await newer;
  resolvers[0]({sequence: {uploaded_flow_records: 1}});
  await first;
  assert.deepStrictEqual(applied, [2], 'stale response overwrote newer state');

  documentRef.hidden = true;
  listeners.visibilitychange();
  await poller.tick();
  assert.strictEqual(calls.length, 2, 'hidden tab polled');
  assert(states.some((item) => item.status === 'paused_hidden'));

  const grouped = CG.normalizeOperationsEvidence({evidence_by_source: {
    uploaded_flow_records: {records: [
      {event_ref: 'a', timestamp: 1}, {event_ref: 'a', timestamp: 1}
    ]},
    suricata_eve: {records: [{event_ref: 'a', timestamp: 2}]},
    demo_data: {records: []}, future_adapters: {records: []},
  }});
  assert.strictEqual(grouped.uploaded_flow_records.length, 1);
  assert.strictEqual(grouped.suricata_eve.length, 1);
  assert.notStrictEqual(grouped.uploaded_flow_records, grouped.suricata_eve);

  let pausedResolve;
  const pausedApplied = [];
  const pausedStates = [];
  const visibleDocument = {
    hidden: false, addEventListener: () => {}, removeEventListener: () => {},
  };
  const pausedPoller = new CG.LiveOperationsPoller({
    fetchSnapshot: () => new Promise((resolve) => { pausedResolve = resolve; }),
    applySnapshot: (value) => pausedApplied.push(value),
    onState: (value) => pausedStates.push(value.status),
    documentRef: visibleDocument,
    setIntervalFn: () => 1, clearIntervalFn: () => {},
  });
  const pausedRequest = pausedPoller.refresh();
  pausedPoller.setPaused(true);
  pausedResolve({sequence: {uploaded_flow_records: 9}});
  await pausedRequest;
  assert.deepStrictEqual(pausedApplied, [], 'manual pause applied a stale response');
  assert.strictEqual(pausedStates.at(-1), 'paused_manual');
})().catch((error) => { console.error(error); process.exit(1); });
"""
    result = subprocess.run(
        ["node", "-e", script], cwd=root, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stdout + result.stderr
