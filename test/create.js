const test = require('tap').test

const ssri = require('..')

test('works just like from', function (t) {
  const integrity = ssri.fromData('hi')
  const integrityCreate = ssri.create().update('hi').digest()

  t.ok(integrityCreate instanceof integrity.constructor, 'should be same Integrity that fromData returns')
  t.equals(integrity + '', integrityCreate + '', 'should be the sam as fromData')
  t.end()
})

test('can pass options', function (t) {
  const integrity = ssri.create({algorithms: ['sha256', 'sha384']}).update('hi').digest()

  t.equals(
    integrity + '',
    'sha256-j0NDRmSPa5bfid2pAcUXaxCm2Dlh3TwayItZstwyeqQ= ' + 
    'sha384-B5EAbfgShHckT1PQ/c4hDbgfVXV1EOJqzuNcGKa86qKNzbv9bcBBubTcextU439S',
    'should be expected value'
  )
  t.end()
})
