'use strict'

const Buffer = require('safe-buffer').Buffer

const test = require('tap').test

const ssri = require('..')

test('toString()', t => {
  const sri = ssri.parse('sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE= sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=')
  t.equal(
    sri.toString(),
    'sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE= sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'integrity objects from ssri.parse() can use toString()'
  )
  t.equal(
    sri.toString({strict: true}),
    'sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'accepts strict mode option'
  )
  t.equal(
    sri.toString({sep: '\n'}),
    'sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE=\nsha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'accepts separator option'
  )
  t.done()
})

test('toJSON()', t => {
  const sri = ssri.parse('sha512-foo sha256-bar!')
  t.equal(
    sri.toJSON(),
    'sha512-foo sha256-bar!',
    'integrity objects from ssri.parse() can use toJSON()'
  )
  t.equal(
    sri.sha512[0].toJSON(),
    'sha512-foo',
    'hash objects should toJSON also'
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
    'concatenates with an Hash-like'
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
  const strictSri = ssri.parse('sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw==')
  t.equal(
    strictSri.concat('sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE=', {
      strict: true
    }).toString(),
    'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw==',
    'accepts strict mode option'
  )
  t.done()
})

test('match()', t => {
  const sri = ssri.parse('sha1-foo sha512-bar')
  t.similar(sri.match('sha1-foo'), {
    algorithm: 'sha1',
    digest: 'foo'
  }, 'returns the matching hash')
  t.similar(sri.match(ssri.parse('sha1-foo')), {
    algorithm: 'sha1',
    digest: 'foo'
  }, 'accepts other Integrity objects')
  t.similar(sri.match(ssri.parse('sha1-foo')), {
    algorithm: 'sha1',
    digest: 'foo'
  }, 'accepts other Hash objects')
  t.similar(sri.match({digest: 'foo', algorithm: 'sha1'}), {
    algorithm: 'sha1',
    digest: 'foo'
  }, 'accepts Hash-like objects')
  t.similar(sri.match('sha1-bar sha512-bar'), {
    algorithm: 'sha512',
    digest: 'bar'
  }, 'returns the strongest match')
  t.notOk(sri.match('sha512-foo'), 'falsy when match fails')
  t.notOk(sri.match('sha384-foo'), 'falsy when match fails')
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
  t.throws(() => {
    ssri.parse('').pickAlgorithm()
  }, /No algorithms available/, 'SRIs without algorithms are invalid')
  t.done()
})

test('hexDigest()', t => {
  t.equal(
    ssri.parse('sha512-foo').hexDigest(),
    Buffer.from('foo', 'base64').toString('hex'),
    'returned hex version of base64 digest')
  t.equal(
    ssri.parse('sha512-bar', {single: true}).hexDigest(),
    Buffer.from('bar', 'base64').toString('hex'),
    'returned hex version of base64 digest')
  t.done()
})

test('isIntegrity and isHash', t => {
  const sri = ssri.parse('sha512-bar')
  t.ok(sri.isIntegrity, 'full sri has !!.isIntegrity')
  t.ok(
    sri['sha512'][0].isHash,
    'sri hash has !!.isHash'
  )
  t.done()
})

test('semi-private', t => {
  t.equal(ssri.Integrity, undefined, 'Integrity class is module-private.')
  t.done()
})
