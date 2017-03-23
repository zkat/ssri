'use strict'

const crypto = require('crypto')
const Transform = require('stream').Transform

const SRI_REGEX = /([^-]+)-([^?]+)([?\S*]*)/

class IntegrityMetadata {
  constructor (metadata) {
    this.source = metadata
    // 3.1. Integrity metadata
    // https://w3c.github.io/webappsec-subresource-integrity/#integrity-metadata-description
    const match = metadata.match(SRI_REGEX)
    if (!match) { return }
    this.algorithm = match[1]
    this.digest = match[2]

    const rawOpts = match[3]
    this.options = rawOpts ? rawOpts.slice(1).split('?') : []
  }
  toString () {
    const opts = this.options && this.options.length
    ? `?${this.options.join('?')}`
    : ''
    return `${this.algorithm}-${this.digest}${opts}`
  }
}

class Integrity {
  toString (sep) {
    sep = sep || ' '
    return Object.keys(this).map(k => {
      return this[k].map(meta => {
        return IntegrityMetadata.prototype.toString.call(meta)
      })
    }).join(sep)
  }
}

module.exports.parse = parse
function parse (integrity) {
  // 3.4.3. Parse metadata
  // https://w3c.github.io/webappsec-subresource-integrity/#parse-metadata
  return integrity.trim().split(/\s+/).reduce((acc, string) => {
    const metadata = new IntegrityMetadata(string)
    if (metadata.algorithm && metadata.digest) {
      const algo = metadata.algorithm
      if (!acc[algo]) { acc[algo] = [] }
      acc[algo].push(metadata)
    }
    return acc
  }, new Integrity())
}

module.exports.serialize = serialize
module.exports.unparse = serialize
function serialize (obj, sep) {
  if (obj.algorithm && obj.digest) {
    return IntegrityMetadata.prototype.toString.call(obj)
  } else {
    return Integrity.prototype.toString.call(obj, sep)
  }
}

module.exports.fromData = fromData
function fromData (data, opts) {
  opts = opts || {}
  const algorithms = opts.algorithms || ['sha512']
  const optString = opts.options && opts.options.length
  ? `?${opts.options.join('?')}`
  : ''
  return algorithms.reduce((acc, algo) => {
    const digest = crypto.createHash(algo).update(data).digest('base64')
    const meta = new IntegrityMetadata(`${algo}-${digest}${optString}`)
    if (meta.algorithm && meta.digest) {
      const algo = meta.algorithm
      if (!acc[algo]) { acc[algo] = [] }
      acc[algo].push(meta)
    }
    return acc
  }, new Integrity())
}

module.exports.fromStream = fromStream
function fromStream (stream, opts) {
  opts = opts || {}
  const algorithms = opts.algorithms || ['sha512']
  const optString = opts.options && opts.options.length
  ? `?${opts.options.join('?')}`
  : ''
  const P = opts.promise || Promise
  return new P((resolve, reject) => {
    const hashes = algorithms.map(algo => crypto.createHash(algo))
    stream.on('data', d => hashes.forEach(hash => hash.update(d)))
    stream.on('error', reject)
    stream.on('end', () => {
      resolve(algorithms.reduce((acc, algo, i) => {
        const hash = hashes[i]
        const digest = hash.digest('base64')
        const meta = new IntegrityMetadata(`${algo}-${digest}${optString}`)
        if (meta.algorithm && meta.digest) {
          const algo = meta.algorithm
          if (!acc[algo]) { acc[algo] = [] }
          acc[algo].push(meta)
        }
        return acc
      }, new Integrity()))
    })
  })
}

module.exports.checkData = checkData
function checkData (data, sri, opts) {
  opts = opts || {}
  if (typeof sri === 'string') {
    sri = parse(sri)
  } else if (sri.algorithm && sri.digest) {
    const fullSri = new Integrity()
    fullSri[sri.algorithm] = [sri]
    sri = fullSri
  }
  const algorithm = Object.keys(sri).reduce((acc, algo) => {
    return getPrioritizedHashFunction(acc, algo) || acc
  })
  const digests = sri[algorithm].map(m => m.digest)
  const digest = crypto.createHash(algorithm).update(data).digest('base64')
  return digests.some(d => d === digest)
}

module.exports.checkStream = checkStream
function checkStream (stream, sri, opts) {
  opts = opts || {}
  const P = opts.Promise || Promise
  const checker = createCheckerStream(sri, opts)
  return new P((resolve, reject) => {
    stream.pipe(checker)
    stream.on('error', reject)
    checker.on('error', reject)
    checker.on('verified', algo => {
      resolve(algo)
    })
  })
}

module.exports.createCheckerStream = createCheckerStream
function createCheckerStream (sri, opts) {
  opts = opts || {}
  if (typeof sri === 'string') {
    sri = parse(sri)
  } else if (sri.algorithm && sri.digest) {
    const fullSri = new Integrity()
    fullSri[sri.algorithm] = [sri]
    sri = fullSri
  }
  const algorithm = Object.keys(sri).reduce((acc, algo) => {
    return getPrioritizedHashFunction(acc, algo) || acc
  })
  const digests = sri[algorithm].map(m => m.digest)
  const hash = crypto.createHash(algorithm)
  const stream = new Transform({
    transform: function (chunk, enc, cb) {
      hash.update(chunk, enc)
      cb(null, chunk, enc)
    },
    flush: function (cb) {
      const digest = hash.digest('base64')
      if (digests.some(d => d === digest)) {
        stream.emit('verified', algorithm)
        return cb()
      } else {
        const err = new Error(`${algorithm} integrity checksum failed`)
        err.code = 'EBADCHECKSUM'
        err.found = digest
        err.expected = digests
        err.algorithm = algorithm
        return cb(err)
      }
    }
  })
  return stream
}

function getPrioritizedHashFunction (algo1, algo2) {
  // Default implementaion is empty
}
