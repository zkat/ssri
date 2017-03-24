# ssri [![npm version](https://img.shields.io/npm/v/ssri.svg)](https://npm.im/ssri) [![license](https://img.shields.io/npm/l/ssri.svg)](https://npm.im/ssri) [![Travis](https://img.shields.io/travis/zkat/ssri.svg)](https://travis-ci.org/zkat/ssri) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/zkat/ssri?svg=true)](https://ci.appveyor.com/project/zkat/ssri) [![Coverage Status](https://coveralls.io/repos/github/zkat/ssri/badge.svg?branch=latest)](https://coveralls.io/github/zkat/ssri?branch=latest)

[`ssri`](https://github.com/zkat/ssri), short for Simple Subresource Integrity,
is a Node.js utility for parsing, unparsing, and generating [Subresource
Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/) hashes.

## Install

`$ npm install --save ssri`

## Table of Contents

* [Example](#example)
* [Features](#features)
* [Contributing](#contributing)
* [API](#api)
  * Parsing & Serializing
    * [`parse`](#parse)
    * [`Integrity#concat`](#integrity-concat)
    * [`Integrity#toString`](#integrity-to-string)
    * [`serialize`](#serialize)
  * Integrity Generation
    * [`fromData`](#from-data)
    * [`fromStream`](#from-stream)
  * Integrity Verification
    * [`checkData`](#check-data)
    * [`checkStream`](#check-stream)
    * [`createCheckerStream`](#create-checker-stream)

### Example

```javascript
const ssri = require('ssri')

const integrity = 'sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo'

// Parsing and serializing
const parsed = ssri.parse(integrity)
parsed.toString() // === integrity
ssri.serialize(parsed) // === integrity (works on non-Integrity objects)

// Async stream functions
ssri.checkStream(fs.createReadStream('./my-file'), parsed).then(...)
ssri.fromStream(fs.createReadStream('./my-file')).then(sri => {
  sri.toString() === parsed.toString()
})
fs.createReadStream('./my-file').pipe(ssri.createCheckerStream(sri))

// Sync data functions
ssri.fromData(fs.readFileSync('./my-file')) // === parsed
ssri.checkData(fs.readFileSync('./my-file'), parsed) // => true
```

### Features

* Parses and unparses SRI strings.
* Generates SRI strings from direct data or Streams.
* Optional use of reserved `option-expression` syntax.
* Multiple entries for the same algorithm.
* Object-based integrity string manipulation.
* Optional strict parsing that follows the spec as closely as possible.

### Contributing

The ssri team enthusiastically welcomes contributions and project participation!
There's a bunch of things you can do if you want to contribute! The [Contributor
Guide](CONTRIBUTING.md) has all the information you need for everything from
reporting bugs to contributing entire new features. Please don't hesitate to
jump in if you'd like to, or even ask us questions if something isn't clear.

### API

#### <a name="parse"></a> `> ssri.parse(sri, [opts]) -> Integrity`

Parses `sri` into an `Integrity` data structure. `sri` can be an integrity
string, an `IntegrityMetadata`-like with `digest` and `algorithm` fields and an
optional `options` field, or an `Integrity`-like object. The resulting object
will be an `Integrity` instance that has this shape:

```javascript
{
  'sha1': [{algorithm: 'sha1', digest: 'deadbeef', options: []}],
  'sha512': [
    {algorithm: 'sha512', digest: 'c0ffee', options: []},
    {algorithm: 'sha512', digest: 'bad1dea', options: ['foo']}
  ],
}
```

If `opts.strict` is truthy, the resulting object will be filtered such that
it strictly follows the Subresource Integrity spec, throwing away any entries
with any invalid components. This also means a restricted set of algorithms
will be used -- the spec limits them to `sha256`, `sha384`, and `sha512`.

Strict mode is recommended if the integrity strings are intended for use in
browsers, or in other situations where strict adherence to the spec is needed.

##### Example

```javascript
ssri.parse('sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo') // -> Integrity
```

#### <a name="integrity-concat"></a> `> Integrity#concat(otherIntegrity, [opts]) -> Integrity`

Concatenates an `Integrity` object with another IntegrityLike, or a string
representing integrity metadata.

This is functionally equivalent to concatenating the string format of both
integrity arguments, and calling [`ssri.parse`](#ssri-parse) on the new string.

If `opts.strict` is true, the new `Integrity` will be created using strict
parsing rules. See [`ssri.parse`](#parse).

##### Example

```javascript
// This will combine the integrity checks for two different versions of
// your index.js file so you can use a single integrity string and serve
// either of these to clients, from a single `<script>` tag.
const desktopIntegrity = ssri.fromData(fs.readFileSync('./index.desktop.js'))
const mobileIntegrity = ssri.fromData(fs.readFileSync('./index.mobile.js'))

// Note that browsers (and ssri) will succeed as long as ONE of the entries
// for the *prioritized* algorithm succeeds. That is, in order for this fallback
// to work, both desktop and mobile *must* use the same `algorithm` values.
desktopIntegrity.concat(mobileIntegrity)
```

#### <a name="integrity-to-string"></a> `> Integrity#toString([opts]) -> String`

Returns the string representation of an `Integrity` object. All metadata entries
will be concatenated in the string by `opts.sep`, which defaults to `' '`.

If you want to serialize an object that didn't from from an `ssri` function,
use [`ssri.serialize()`](#serialize).

If `opts.strict` is true, the integrity string will be created using strict
parsing rules. See [`ssri.parse`](#parse).

##### Example

```javascript
const integrity = 'sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo'

ssri.parse(integrity).toString() === integrity
```

#### <a name="serialize"></a> `> ssri.serialize(sri, [opts]) -> String`

This function is identical to [`Integrity#toString()`](#integrity-to-string),
except it can be used on _any_ object that [`parse`](#parse) can handle -- that
is, a string, an `IntegrityMetadata`-like, or an `Integrity`-like.

The `opts.sep` option defines the string to use when joining multiple entries
together. To be spec-compliant, this _must_ be whitespace. The default is a
single space (`' '`).

If `opts.strict` is true, the integrity string will be created using strict
parsing rules. See [`ssri.parse`](#parse).

##### Example

```javascript
// IntegrityMetadata-like: only a single entry.
ssri.serialize({
  algorithm: 'sha512',
  digest:'9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==',
  options: ['foo']
})
// ->
// 'sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo'

// Integrity-like: full multi-entry syntax. Similar to output of `ssri.parse`
ssri.serialize({
  'sha512': [
    {
      algorithm: 'sha512',
      digest:'9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==',
      options: ['foo']
    }
  ]
})
// ->
// 'sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo'
```

#### <a name="from-data"></a> `> ssri.fromData(data, [opts]) -> Integrity`

Creates an `Integrity` object from either string or `Buffer` data, calculating
all the requested hashes and adding any specified options to the object.

`opts.algorithms` determines which algorithms to generate metadata for. All
results will be included in a single `Integrity` object. The default value for
`opts.algorithms` is `['sha512']`. All algorithm strings must be hashes listed
in `crypto.getHashes()` for the host Node.js platform.

`opts.options` may optionally be passed in: it must be an array of option
strings that will be added to all generated integrity metadata generated by
`fromData`. This is a loosely-specified feature of SRIs, and currently has no
specified semantics besides being `?`-separated. Use at your own risk, and
probably avoid if your integrity strings are meant to be used with browsers.

If `opts.strict` is true, the integrity object will be created using strict
parsing rules. See [`ssri.parse`](#parse).

##### Example

```javascript
const integrityObj = ssri.fromData('foobarbaz', {
  algorithms: ['sha256', 'sha384', 'sha512']
})
integrity.toString('\n')
// ->
// sha256-l981iLWj8kurw4UbNy8Lpxqdzd7UOxS50Glhv8FwfZ0=
// sha384-irnCxQ0CfQhYGlVAUdwTPC9bF3+YWLxlaDGM4xbYminxpbXEq+D+2GCEBTxcjES9
// sha512-yzd8ELD1piyANiWnmdnpCL5F52f10UfUdEkHywVZeqTt0ymgrxR63Qz0GB7TKPoeeZQmWCaz7T1+9vBnypkYWg==
```

#### <a name="from-stream"></a> `> ssri.fromStream(stream, [opts]) -> Promise<Integrity>`

Returns a Promise of an Integrity object calculated by reading data from
a given `stream`.

It accepts both `opts.algorithms` and `opts.options`, which are documented as
part of [`ssri.fromData`](#from-data).

Additionally, `opts.Promise` may be passed in to inject a Promise library of
choice. By default, ssri will use Node's built-in Promises.

If `opts.strict` is true, the integrity object will be created using strict
parsing rules. See [`ssri.parse`](#parse).

##### Example

```javascript
ssri.fromStream(fs.createReadStream('index.js'), {
  algorithms: ['sha1', 'sha512']
}).then(integrity => {
  return ssri.checkStream(fs.createReadStream('index.js'), integrity)
}) // succeeds
```

#### <a name="check-data"></a> `> ssri.checkData(data, sri, [opts]) -> Algorithm|false`

Verifies `data` integrity against an `sri` argument. `data` may be either a
`String` or a `Buffer`, and `sri` can be any subresource integrity
representation that [`ssri.parse`](#parse) can handle.

If verification succeeds, `checkData` will return the name of the algorithm that
was used for verification (a truthy value). Otherwise, it will return `false`.

If `opts.pickAlgorithm` is provided, it will be passed two algorithms as
arguments. ssri will prioritize whichever of the two algorithms is returned by
this function. Note that the function may be called multiple times, and it
**must** return one of the two algorithms provided. By default, ssri will make
a best-effort to pick the strongest/most reliable of the given algorithms. It
may intentionally deprioritize algorithms with known vulnerabilities.

##### Example

```javascript
const data = fs.readFileSync('index.js')
ssri.checkData(data, ssri.fromData(data)) // -> 'sha512'
ssri.checkData(data, 'sha256-l981iLWj8kurw4UbNy8Lpxqdzd7UOxS50Glhv8FwfZ0')
ssri.checkData(data, 'sha1-BaDDigEST') // -> false
```

#### <a name="check-stream"></a> `> ssri.checkStream(stream, sri, [opts]) -> Promise<Algorithm>`

Verifies the contents of `stream` against an `sri` argument. `stream` will be
consumed in its entirety by this process. `sri` can be any subresource integrity
representation that [`ssri.parse`](#parse) can handle.

`checkStream` will return a Promise that either resolves to the string name of
the algorithm that verification was done with, or, if the verification fails or
an error happens with `stream`, the Promise will be rejected.

If the Promise is rejected because verification failed, the returned error will
have `err.code` as `EBADCHECKSUM`.

If `opts.pickAlgorithm` is provided, it will be passed two algorithms as
arguments. ssri will prioritize whichever of the two algorithms is returned by
this function. Note that the function may be called multiple times, and it
**must** return one of the two algorithms provided. By default, ssri will make
a best-effort to pick the strongest/most reliable of the given algorithms. It
may intentionally deprioritize algorithms with known vulnerabilities.

##### Example

```javascript
const integrity = ssri.fromData(fs.readFileSync('index.js'))

ssri.checkStream(
  fs.createReadStream('index.js'),
  integrity
) // -> Promise<'sha512'>

ssri.checkStream(
  fs.createReadStream('index.js'),
  'sha256-l981iLWj8kurw4UbNy8Lpxqdzd7UOxS50Glhv8FwfZ0'
) // -> Promise<'sha256'>

ssri.checkStream(
  fs.createReadStream('index.js'),
  'sha1-BaDDigEST'
) // -> Promise<Error<EBADCHECKSUM>>
```

#### <a name="create-checker-stream"></a> `> createCheckerStream(sri, [opts]) -> CheckerStream`

Returns a `Through` stream that data can be piped through in order to check it
against `sri`. `sri` can be any subresource integrity representation that
[`ssri.parse`](#parse) can handle.

If verification fails, the returned stream will error with an `EBADCHECKSUM`
error code.

If `opts.pickAlgorithm` is provided, it will be passed two algorithms as
arguments. ssri will prioritize whichever of the two algorithms is returned by
this function. Note that the function may be called multiple times, and it
**must** return one of the two algorithms provided. By default, ssri will make
a best-effort to pick the strongest/most reliable of the given algorithms. It
may intentionally deprioritize algorithms with known vulnerabilities.

##### Example

```javascript
const integrity = ssri.fromData(fs.readFileSync('index.js'))
fs.createReadStream('index.js')
.pipe(ssri.checkStream(integrity))
```
