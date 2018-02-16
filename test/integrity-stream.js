'use strict'

const test = require('tap').test

const ssri = require('..')

test('generates integrity', t => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream()
  stream.write('foo')
  let collected = ''
  stream.on('data', d => { collected += d.toString() })
  let integrity
  stream.on('integrity', i => { integrity = i })
  stream.on('end', () => {
    t.equal(collected, 'foo', 'stream output is complete')
    t.deepEqual(integrity, TARGET, 'matching integrity emitted')
    t.done()
  })
  stream.end()
})

test('optional algorithms option', t => {
  const TARGET = ssri.fromData('foo', {algorithms: ['sha1', 'sha256']})
  const stream = ssri.integrityStream({algorithms: ['sha1', 'sha256']})
  stream.write('foo')
  stream.on('data', () => {})
  let integrity
  stream.on('integrity', i => { integrity = i })
  stream.on('end', () => {
    t.deepEqual(integrity, TARGET, 'matching integrity emitted')
    t.done()
  })
  stream.end()
})

test('verification for correct data succeeds', t => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream({
    integrity: TARGET
  })
  stream.write('foo')
  let collected = ''
  stream.on('data', d => { collected += d.toString() })
  let integrity
  stream.on('integrity', i => { integrity = i })
  stream.on('end', () => {
    t.equal(collected, 'foo', 'stream output is complete')
    t.deepEqual(integrity, TARGET, 'matching integrity emitted')
    t.done()
  })
  stream.end()
})

test('verification for wrong data fails', t => {
  const stream = ssri.integrityStream({
    integrity: ssri.fromData('bar')
  })
  stream.write('foo')
  stream.on('data', () => {})
  stream.on('error', err => {
    t.equal(err.code, 'EINTEGRITY', 'errors with EINTEGRITY on mismatch')
    t.done()
  })
  stream.end()
})
