const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const scope = {module: {exports: {}}};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), scope);
const model = scope.module.exports;

test('capture moves left at the rate of elapsed real time', () => {
  const before = model.sampleX(240, 480, 1000, 1000, 300, 1200);
  const after = model.sampleX(240, 480, 1000, 1002, 300, 1200);
  assert.equal(before - after, 8);
});

test('simultaneous SSH and account events keep independent profiles', () => {
  const result = model.buildProfiles([{time: 990, technique: 'Attk101'}, {time: 990, technique: 'Attk102'}], 1000, 300);
  assert.ok(Math.max(...result.profiles.Attk101) > 0);
  assert.deepEqual(result.profiles.Attk101, result.profiles.Attk102);
  assert.ok(result.profiles.Attk103.every(value => value === 0));
});

test('empty and expired activity produce no invented wave', () => {
  const result = model.buildProfiles([{time: 600, technique: 'Attk101'}], 1000, 300);
  assert.ok(Object.values(result.profiles).flat().every(value => value === 0));
});

test('normal baseline activity also moves as a low trace', () => {
  const result = model.buildSeries([{time: 990}, {time: 995}], 1000, 300);
  assert.ok(Math.max(...result.values) > 0);
  const before = model.sampleX(240, 480, result.end, 1000, result.seconds, 1200);
  const after = model.sampleX(240, 480, result.end, 1002, result.seconds, 1200);
  assert.equal(before - after, 8);
});

test('individual attempts remain distinct at live capture resolution', () => {
  const result = model.buildProfiles([{time: 970, technique: 'Attk101'}, {time: 985, technique: 'Attk101'}], 1000, 300);
  const middle = Math.round((977.5 - 700) / 300 * 479);
  assert.ok(result.profiles.Attk101[middle] < 0.001);
  assert.ok(Math.max(...result.profiles.Attk101) > 0.8);
});
