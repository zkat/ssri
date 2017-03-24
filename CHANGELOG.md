# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

<a name="2.0.0"></a>
# [2.0.0](https://github.com/zkat/ssri/compare/v1.0.0...v2.0.0) (2017-03-24)


### Bug Fixes

* **strict-mode:** make regexes more rigid ([122a32c](https://github.com/zkat/ssri/commit/122a32c))


### Features

* **api:** added serialize alias for unparse ([999b421](https://github.com/zkat/ssri/commit/999b421))
* **concat:** add Integrity#concat() ([cae12c7](https://github.com/zkat/ssri/commit/cae12c7))
* **pickAlgo:** pick the strongest algorithm provided, by default ([58c18f7](https://github.com/zkat/ssri/commit/58c18f7))
* **strict-mode:** strict SRI support ([3f0b64c](https://github.com/zkat/ssri/commit/3f0b64c))
* **stringify:** replaced unparse/serialize with stringify ([4acad30](https://github.com/zkat/ssri/commit/4acad30))
* **verification:** add opts.pickAlgorithm ([f72e658](https://github.com/zkat/ssri/commit/f72e658))


### BREAKING CHANGES

* **pickAlgo:** ssri will prioritize specific hashes now
* **stringify:** serialize and unparse have been removed. Use ssri.stringify instead.
* **strict-mode:** functions that accepted an optional `sep` argument now expect `opts.sep`.



<a name="1.0.0"></a>
# 1.0.0 (2017-03-23)


### Features

* **api:** implemented initial api ([4fbb16b](https://github.com/zkat/ssri/commit/4fbb16b))


### BREAKING CHANGES

* **api:** Initial API established.
