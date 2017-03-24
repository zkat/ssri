'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

function fileStream () {
  return fs.createReadStream(__filename)
}

test('checkData', t => {
  const sri = ssri.parse({
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512')
  })
  t.equal(
    ssri.checkData(TEST_DATA, sri),
    'sha512',
    'Buffer data successfully verified'
  )
  t.equal(
    ssri.checkData(TEST_DATA, `sha512-${hash(TEST_DATA, 'sha512')}`),
    'sha512',
    'Accepts string SRI'
  )
  t.equal(
    ssri.checkData(TEST_DATA, {
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512')
    }),
    'sha512',
    'Accepts IntegrityMetadata-like SRI'
  )
  t.equal(
    ssri.checkData(TEST_DATA.toString('utf8'), sri),
    'sha512',
    'String data successfully verified'
  )
  t.equal(
    ssri.checkData(
      TEST_DATA,
      `sha512-nope sha512-${hash(TEST_DATA, 'sha512')}`
    ),
    'sha512',
    'succeeds if any of the hashes under the chosen algorithm match'
  )
  t.equal(
    ssri.checkData('nope', sri),
    false,
    'returns false when verification fails'
  )
  t.equal(
    ssri.checkData(TEST_DATA, [
      'sha512-nope',
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha512-${hash(TEST_DATA, 'sha512')}`
    ].join(' '), {
      pickAlgorithm: (a, b) => {
        if (a === 'sha1' || b === 'sha1') { return 'sha1' }
      }
    }),
    'sha1',
    'opts.pickAlgorithm can be used to customize which one is used.'
  )
  t.equal(
    ssri.checkData(TEST_DATA, [
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha384-${hash(TEST_DATA, 'sha384')}`,
      `sha256-${hash(TEST_DATA, 'sha256')}`
    ].join(' ')),
    'sha384',
    'picks the "strongest" available algorithm, by default'
  )
  t.done()
})

test('checkStream', t => {
  const sri = ssri.parse({
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512')
  })
  let streamEnded
  const stream = fileStream().on('end', () => { streamEnded = true })
  return ssri.checkStream(stream, sri).then(algo => {
    t.equal(algo, 'sha512', 'Stream data successfully verified')
    t.ok(streamEnded, 'source stream ended')
    return ssri.checkStream(
      fileStream(),
      `sha512-${hash(TEST_DATA, 'sha512')}`
    )
  }).then(algo => {
    t.equal(algo, 'sha512', 'Accepts string SRI')
    return ssri.checkStream(fileStream(), {
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512')
    })
  }).then(algo => {
    t.equal(algo, 'sha512', 'Accepts IntegrityMetadata-like SRI')
    return ssri.checkStream(
      fileStream(),
      `sha512-nope sha512-${hash(TEST_DATA, 'sha512')}`
    )
  }).then(algo => {
    t.equal(
      algo,
      'sha512',
      'succeeds if any of the hashes under the chosen algorithm match'
    )
    return ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      sri
    ).then(() => {
      throw new Error('unexpected success')
    }, err => {
      t.equal(err.code, 'EBADCHECKSUM', 'checksum failure rejects the promise')
    })
  }).then(() => {
    return ssri.checkStream(fileStream(), [
      'sha512-nope',
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha512-${hash(TEST_DATA, 'sha512')}`
    ].join(' '), {
      pickAlgorithm: (a, b) => {
        if (a === 'sha1' || b === 'sha1') { return 'sha1' }
      }
    })
  }).then(algo => {
    t.equal(
      algo,
      'sha1',
      'opts.pickAlgorithm can be used to customize which one is used.'
    )
    return ssri.checkStream(fileStream(), [
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha384-${hash(TEST_DATA, 'sha384')}`,
      `sha256-${hash(TEST_DATA, 'sha256')}`
    ].join(' '))
  }).then(algo => {
    t.equal(
      algo,
      'sha384',
      'picks the "strongest" available algorithm, by default'
    )
  })
})
