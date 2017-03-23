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
    * [`unparse`](#unparse)
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
ssri.unparse(parsed) // === integrity (works on non-Integrity objects)

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
* Optional use of reserved option expression syntax.
* Multiple entries for the same algorithm.

### Contributing

The ssri team enthusiastically welcomes contributions and project participation! There's a bunch of things you can do if you want to contribute! The [Contributor Guide](CONTRIBUTING.md) has all the information you need for everything from reporting bugs to contributing entire new features. Please don't hesitate to jump in if you'd like to, or even ask us questions if something isn't clear.

### API
