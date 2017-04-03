'use strict'

const crypto = require('crypto')
const fs = require('fs')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

test('serializes Integrity-likes', t => {
  const sriLike = {
    'sha512': [{
      digest: 'foo',
      algorithm: 'sha512',
      options: ['ayy', 'woo']
    }, {
      digest: 'bar',
      algorithm: 'sha512'
    }],
    'whirlpool': [{
      digest: 'wut',
      algorithm: 'whirlpool'
    }]
  }
  t.equal(
    ssri.stringify(sriLike),
    'sha512-foo?ayy?woo sha512-bar whirlpool-wut',
    'stringification contains correct data for all entries'
  )
  t.done()
})

test('serializes Hash-likes', t => {
  const sriLike = {
    digest: 'foo',
    algorithm: 'sha512'
  }
  t.equal(
    ssri.stringify(sriLike),
    'sha512-foo',
    'serialization has correct data'
  )
  t.done()
})

test('serialized plain strings into a valid parsed version', t => {
  const sri = ' \tsha512-foo?bar    \n\n\nsha1-nope\r'
  t.equal(
    ssri.stringify(sri),
    'sha512-foo?bar sha1-nope',
    'cleaned-up string with identical contents generated'
  )
  t.done()
})

test('accepts a separator opt', t => {
  const sriLike = {
    'sha512': [{
      algorithm: 'sha512',
      digest: 'foo'
    }, {
      algorithm: 'sha512',
      digest: 'bar'
    }]
  }
  t.equal(
    ssri.stringify(sriLike, {sep: '\n'}),
    'sha512-foo\nsha512-bar'
  )
  t.equal(
    ssri.stringify(sriLike, {sep: ' | '}),
    'sha512-foo | sha512-bar'
  )
  t.done()
})

test('support strict serialization', t => {
  const sriLike = {
    // only sha256, sha384, and sha512 are allowed by the spec
    'sha1': [{
      algorithm: 'sha1',
      digest: 'feh'
    }],
    'sha256': [{
      algorithm: 'sha256',
      // Must be valid base64
      digest: 'wut!!!??!!??!'
    }, {
      algorithm: 'sha256',
      digest: hash(TEST_DATA, 'sha256'),
      options: ['foo']
    }],
    'sha512': [{
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
      // Options must use VCHAR
      options: ['\x01']
    }]
  }
  t.equal(
    ssri.stringify(sriLike, {strict: true}),
    `sha256-${hash(TEST_DATA, 'sha256')}?foo`,
    'entries that do not conform to strict spec interpretation removed'
  )
  t.equal(
    ssri.stringify('sha512-foo sha256-bar', {sep: ' \r|\n\t', strict: true}),
    'sha512-foo \r \n\tsha256-bar',
    'strict mode replaces non-whitespace characters in separator with space'
  )
  t.done()
})
