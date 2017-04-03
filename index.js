'use strict'

const crypto = require('crypto')
const Transform = require('stream').Transform

const SPEC_ALGORITHMS = ['sha256', 'sha384', 'sha512']

const BASE64_REGEX = /^[a-z0-9+/]+(?:=?=?)$/i
const SRI_REGEX = /^([^-]+)-([^?]+)([?\S*]*)$/
const STRICT_SRI_REGEX = /^([^-]+)-([A-Za-z0-9+/]+(?:=?=?))([?\x21-\x7E]*)$/
const VCHAR_REGEX = /^[\x21-\x7E]+$/

class IntegrityMetadata {
  get isIntegrityMetadata () { return true }
  constructor (metadata, opts) {
    const strict = !!(opts && opts.strict)
    this.source = metadata.trim()
    // 3.1. Integrity metadata
    // https://w3c.github.io/webappsec-subresource-integrity/#integrity-metadata-description
    const match = this.source.match(
      strict
      ? STRICT_SRI_REGEX
      : SRI_REGEX
    )
    if (!match) { return }
    if (strict && !SPEC_ALGORITHMS.some(a => a === match[1])) { return }
    this.algorithm = match[1]
    this.digest = match[2]

    const rawOpts = match[3]
    this.options = rawOpts ? rawOpts.slice(1).split('?') : []
  }
  hexDigest () {
    return this.digest && bufFrom(this.digest, 'base64').toString('hex')
  }
  toString (opts) {
    if (opts && opts.strict) {
      // Strict mode enforces the standard as close to the foot of the
      // letter as it can.
      if (!(
        // The spec has very restricted productions for algorithms.
        // https://www.w3.org/TR/CSP2/#source-list-syntax
        SPEC_ALGORITHMS.some(x => x === this.algorithm) &&
        // Usually, if someone insists on using a "different" base64, we
        // leave it as-is, since there's multiple standards, and the
        // specified is not a URL-safe variant.
        // https://www.w3.org/TR/CSP2/#base64_value
        this.digest.match(BASE64_REGEX) &&
        // Option syntax is strictly visual chars.
        // https://w3c.github.io/webappsec-subresource-integrity/#grammardef-option-expression
        // https://tools.ietf.org/html/rfc5234#appendix-B.1
        (this.options || []).every(opt => opt.match(VCHAR_REGEX))
      )) {
        return ''
      }
    }
    const options = this.options && this.options.length
    ? `?${this.options.join('?')}`
    : ''
    return `${this.algorithm}-${this.digest}${options}`
  }
}

class Integrity {
  get isIntegrity () { return true }
  toString (opts) {
    opts = opts || {}
    let sep = opts.sep || ' '
    if (opts.strict) {
      // Entries must be separated by whitespace, according to spec.
      sep = sep.replace(/\S+/g, ' ')
    }
    return Object.keys(this).map(k => {
      return this[k].map(meta => {
        return IntegrityMetadata.prototype.toString.call(meta, opts)
      }).filter(x => x.length).join(sep)
    }).filter(x => x.length).join(sep)
  }
  concat (integrity, opts) {
    const other = typeof integrity === 'string'
    ? integrity
    : stringify(integrity, opts)
    return parse(`${this.toString(opts)} ${other}`, opts)
  }
  hexDigest () {
    return parse(this, {single: true}).hexDigest()
  }
  pickAlgorithm (opts) {
    const pickAlgorithm = (opts && opts.pickAlgorithm) || getPrioritizedHash
    return Object.keys(this).reduce((acc, algo) => {
      return pickAlgorithm(acc, algo) || acc
    })
  }
}

module.exports.parse = parse
function parse (sri, opts) {
  opts = opts || {}
  if (typeof sri === 'string') {
    return _parse(sri, opts)
  } else if (sri.algorithm && sri.digest) {
    const fullSri = new Integrity()
    fullSri[sri.algorithm] = [sri]
    return _parse(stringify(fullSri, opts), opts)
  } else {
    return _parse(stringify(sri, opts), opts)
  }
}

function _parse (integrity, opts) {
  // 3.4.3. Parse metadata
  // https://w3c.github.io/webappsec-subresource-integrity/#parse-metadata
  if (opts.single) {
    return new IntegrityMetadata(integrity, opts)
  }
  return integrity.trim().split(/\s+/).reduce((acc, string) => {
    const metadata = new IntegrityMetadata(string, opts)
    if (metadata.algorithm && metadata.digest) {
      const algo = metadata.algorithm
      if (!acc[algo]) { acc[algo] = [] }
      acc[algo].push(metadata)
    }
    return acc
  }, new Integrity())
}

module.exports.stringify = stringify
function stringify (obj, opts) {
  if (obj.algorithm && obj.digest) {
    return IntegrityMetadata.prototype.toString.call(obj, opts)
  } else if (typeof obj === 'string') {
    return stringify(parse(obj, opts), opts)
  } else {
    return Integrity.prototype.toString.call(obj, opts)
  }
}

module.exports.fromHex = fromHex
function fromHex (hexDigest, algorithm, opts) {
  const optString = (opts && opts.options && opts.options.length)
  ? `?${opts.options.join('?')}`
  : ''
  return parse(
    `${algorithm}-${
      bufFrom(hexDigest, 'hex').toString('base64')
    }${optString}`, opts
  )
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
    const meta = new IntegrityMetadata(
      `${algo}-${digest}${optString}`,
       opts
    )
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
  const P = opts.Promise || Promise
  const istream = integrityStream(opts)
  return new P((resolve, reject) => {
    stream.pipe(istream)
    stream.on('error', reject)
    istream.on('error', reject)
    let sri
    istream.on('integrity', s => { sri = s })
    istream.on('end', () => resolve(sri))
    istream.on('data', () => {})
  })
}

module.exports.checkData = checkData
function checkData (data, sri, opts) {
  opts = opts || {}
  sri = parse(sri, opts)
  const algorithm = sri.pickAlgorithm(opts)
  const digests = sri[algorithm]
  const digest = crypto.createHash(algorithm).update(data).digest('base64')
  return digests.find(meta => meta.digest === digest) || false
}

module.exports.checkStream = checkStream
function checkStream (stream, sri, opts) {
  opts = opts || {}
  const P = opts.Promise || Promise
  const checker = integrityStream({
    integrity: sri,
    size: opts.size,
    strict: opts.strict,
    pickAlgorithm: opts.pickAlgorithm
  })
  return new P((resolve, reject) => {
    stream.pipe(checker)
    stream.on('error', reject)
    checker.on('error', reject)
    let sri
    checker.on('verified', s => { sri = s })
    checker.on('end', () => resolve(sri))
    checker.on('data', () => {})
  })
}

module.exports.integrityStream = integrityStream
function integrityStream (opts) {
  opts = opts || {}
  // For verification
  const sri = opts.integrity && parse(opts.integrity, opts)
  const algorithm = sri && sri.pickAlgorithm(opts)
  const digests = sri && sri[algorithm]
  // Calculating stream
  const algorithms = opts.algorithms || [algorithm || 'sha512']
  const hashes = algorithms.map(crypto.createHash)
  let streamSize = 0
  const stream = new Transform({
    transform (chunk, enc, cb) {
      streamSize += chunk.length
      hashes.forEach(h => h.update(chunk, enc))
      cb(null, chunk, enc)
    },
    flush (done) {
      const optString = (opts.options && opts.options.length)
      ? `?${opts.options.join('?')}`
      : ''
      const newSri = parse(hashes.map((h, i) => {
        return `${algorithms[i]}-${h.digest('base64')}${optString}`
      }).join(' '), opts)
      const match = (
        // Integrity verification mode
        opts.integrity &&
        digests.find(meta => {
          return newSri[algorithm].find(newmeta => {
            return meta.digest === newmeta.digest
          })
        })
      )
      if (typeof opts.size === 'number' && streamSize !== opts.size) {
        const err = new Error(`stream size mismatch when checking ${sri}.\n  Wanted: ${opts.size}\n  Found: ${streamSize}`)
        err.code = 'EBADSIZE'
        err.found = streamSize
        err.expected = opts.size
        err.sri = sri
        stream.emit('error', err)
      } else if (opts.integrity && !match) {
        const err = new Error(`${sri} integrity checksum failed when using ${algorithm}`)
        err.code = 'EBADCHECKSUM'
        err.found = newSri
        err.expected = digests
        err.algorithm = algorithm
        err.sri = sri
        stream.emit('error', err)
      } else {
        stream.emit('size', streamSize)
        stream.emit('integrity', newSri)
        match && stream.emit('verified', match)
      }
      done()
    }
  })
  return stream
}

// This is a Best Effort™ at a reasonable priority for hash algos
const DEFAULT_PRIORITY = [
  'md5', 'whirlpool', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'
]
function getPrioritizedHash (algo1, algo2) {
  return DEFAULT_PRIORITY.indexOf(algo1.toLowerCase()) >= DEFAULT_PRIORITY.indexOf(algo2.toLowerCase())
  ? algo1
  : algo2
}

function bufFrom (data, enc) {
  return Buffer.from ? Buffer.from(data, enc) : new Buffer(data, enc)
}
