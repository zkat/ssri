'use strict'

const test = require('tap').test

const ssri = require('..')

test('toString()', t => {
  const sri = ssri.parse('sha512-foo sha256-bar!')
  t.equal(
    sri.toString(),
    'sha512-foo sha256-bar!',
    'integrity objects from ssri.parse() can use toString()'
  )
  t.equal(
    sri.toString({strict: true}),
    'sha512-foo',
    'accepts strict mode option'
  )
  t.equal(
    sri.toString({sep: '\n'}),
    'sha512-foo\nsha256-bar!',
    'accepts separator option'
  )
  t.done()
})

test('concat()', t => {
  const sri = ssri.parse('sha512-foo')
  t.equal(
    sri.concat('sha512-bar').toString(),
    'sha512-foo sha512-bar',
    'concatenates with a string'
  )
  t.equal(
    sri.concat({digest: 'bar', algorithm: 'sha384'}).toString(),
    'sha512-foo sha384-bar',
    'concatenates with an IntegrityMetadata-like'
  )
  t.equal(
    sri.concat({
      'sha384': [{digest: 'bar', algorithm: 'sha384'}],
      'sha1': [{digest: 'baz', algorithm: 'sha1'}]
    }).toString(),
    'sha512-foo sha384-bar sha1-baz',
    'concatenates with an Integrity-like'
  )
  t.equal(
    sri.concat(
      {digest: 'bar', algorithm: 'sha1'}
    ).concat(
      'sha1-baz'
    ).concat(
      'sha512-quux'
    ).toString(),
    'sha512-foo sha512-quux sha1-bar sha1-baz',
    'preserves relative order for algorithms between different concatenations'
  )
  t.equal(
    sri.concat('sha1-bar!', {strict: true}).toString(),
    'sha512-foo',
    'accepts strict mode option'
  )
  t.done()
})

test('pickAlgorithm()', t => {
  const sri = ssri.parse('sha1-foo sha512-bar sha384-baz')
  t.equal(sri.pickAlgorithm(), 'sha512', 'picked best algorithm')
  t.equal(
    ssri.parse('unknown-deadbeef uncertain-bada55').pickAlgorithm(),
    'unknown',
    'unrecognized algorithm returned if none others known'
  )
  t.equal(
    sri.pickAlgorithm({
      pickAlgorithm: (a, b) => 'sha384'
    }),
    'sha384',
    'custom pickAlgorithm function accepted'
  )
  t.done()
})

test('IntegrityMetadata.hexDigest()', t => {
  const sri = ssri.parse('sha512-bar', {single: true})
  t.equal(
    sri.hexDigest(),
    (
      Buffer.from ? Buffer.from('bar', 'base64') : new Buffer('bar', 'base64')
    ).toString('hex'),
    'returned hex version of base64 digest')
  t.done()
})

test('isIntegrity and isIntegrityMetadata', t => {
  const sri = ssri.parse('sha512-bar')
  t.ok(sri.isIntegrity, 'full sri has !!.isIntegrity')
  t.ok(
    sri['sha512'][0].isIntegrityMetadata,
    'sri hash has !!.isIntegrityMetadata'
  )
  t.done()
})

test('semi-private', t => {
  t.equal(ssri.Integrity, undefined, 'Integrity class is module-private.')
  t.done()
})
