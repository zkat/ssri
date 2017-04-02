'use strict'

const crypto = require('crypto')
const fs = require('fs')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

test('parses single-entry integrity string', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  t.deepEqual(ssri.parse(integrity), {
    'sha512': [{
      source: integrity,
      digest: sha,
      algorithm: 'sha512',
      options: []
    }]
  }, 'single entry parsed into full Integrity instance')
  t.done()
})

test('can parse single-entry string directly into IntegrityMetadata', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  t.deepEqual(ssri.parse(integrity, {single: true}), {
    source: integrity,
    digest: sha,
    algorithm: 'sha512',
    options: []
  }, 'single entry parsed into single IntegrityMetadata instance')
  t.done()
})

test('accepts IntegrityMetadata-likes as input', t => {
  const algorithm = 'sha512'
  const digest = hash(TEST_DATA, 'sha512')
  const sriLike = {
    algorithm,
    digest,
    options: ['foo']
  }
  const parsed = ssri.parse(sriLike)
  t.deepEqual(parsed, {
    'sha512': [{
      source: `sha512-${digest}?foo`,
      algorithm,
      digest,
      options: ['foo']
    }]
  }, 'Metadata-like returned as full Integrity instance')
  t.done()
})

test('accepts Integrity-like as input', t => {
  const algorithm = 'sha512'
  const digest = hash(TEST_DATA, 'sha512')
  const sriLike = {
    'sha512': [{
      algorithm,
      digest,
      options: ['foo']
    }]
  }
  const parsed = ssri.parse(sriLike)
  t.deepEqual(parsed, {
    'sha512': [{
      source: `sha512-${digest}?foo`,
      algorithm,
      digest,
      options: ['foo']
    }]
  }, 'Integrity-like returned as full Integrity instance')
  t.notEqual(parsed, sriLike, 'Objects are separate instances.')
  t.done()
})

test('parses and groups multiple-entry strings', t => {
  const hashes = [
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha256-${hash(TEST_DATA, 'sha256')}`,
    `sha1-OthERhaSh`,
    `unknown-WoWoWoWoW`
  ]
  t.deepEqual(ssri.parse(hashes.join(' ')), {
    'sha1': [{
      source: hashes[0],
      digest: hashes[0].split('-')[1],
      algorithm: 'sha1',
      options: []
    }, {
      source: hashes[2],
      digest: hashes[2].split('-')[1],
      algorithm: 'sha1',
      options: []
    }],
    'sha256': [{
      source: hashes[1],
      digest: hashes[1].split('-')[1],
      algorithm: 'sha256',
      options: []
    }],
    'unknown': [{
      source: hashes[3],
      digest: hashes[3].split('-')[1],
      algorithm: 'unknown',
      options: []
    }]
  })
  t.done()
})

test('parses any whitespace as entry separators', t => {
  const integrity = `\tsha512-foobarbaz \n\rsha384-bazbarfoo\n         \t  \t\t sha256-foo`
  t.deepEqual(ssri.parse(integrity), {
    'sha512': [{
      source: 'sha512-foobarbaz',
      algorithm: 'sha512',
      digest: 'foobarbaz',
      options: []
    }],
    'sha384': [{
      source: 'sha384-bazbarfoo',
      algorithm: 'sha384',
      digest: 'bazbarfoo',
      options: []
    }],
    'sha256': [{
      source: 'sha256-foo',
      algorithm: 'sha256',
      digest: 'foo',
      options: []
    }]
  }, 'whitespace around metadata skipped and trimmed')
  t.done()
})

test('discards invalid format entries', t => {
  const missingDash = `thisisbad`
  const missingAlgorithm = `-deadbeef`
  const missingDigest = `sha512-`
  const valid = `sha512-${hash(TEST_DATA, 'sha512')}`
  t.equal(ssri.parse([
    missingDash,
    missingAlgorithm,
    missingDigest,
    valid
  ].join(' ')).toString(), valid, 'invalid entries thrown out')
  t.done()
})

test('trims whitespace from either end', t => {
  const integrity = `      sha512-${hash(TEST_DATA, 'sha512')}    `
  t.deepEqual(ssri.parse(integrity), {
    'sha512': [{
      source: integrity.trim(),
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
      options: []
    }]
  }, 'whitespace is trimmed from source before parsing')
  t.done()
})

test('supports strict spec parsing', t => {
  const valid = `sha512-${hash(TEST_DATA, 'sha512')}`
  const badAlgorithm = `sha1-${hash(TEST_DATA, 'sha1')}`
  const badBase64 = `sha512-@#$@%#$`
  const badOpts = `${valid}?\x01\x02`
  t.deepEqual(ssri.parse([
    badAlgorithm,
    badBase64,
    badOpts,
    valid
  ].join(' '), {
    strict: true
  }).toString(), valid, 'entries that fail strict check rejected')
  t.done()
})
