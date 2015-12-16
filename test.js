var crypto = require('crypto')
var cl = require('./build/Release/nodetweetnacl.node')

var na = require('chloridedown/build/Release/sodium')

function Z (l) {
  var b = new Buffer(l)
  b.fill(0)
  return b
}

var h = new Buffer (64)
function hash (msg) {
  cl.crypto_hash(h, msg)
  return h
}

hash(h, new Buffer('abc'))
var nonce = Z(24)
var key   = Z(32)
var input = new Buffer('hello worldxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
var output = Z(input.length+32)
//console.log(cl.crypto_secretbox(output, input, nonce, key)) 

console.log(input.toString('hex'))
var ctext = na.crypto_secretbox(input, nonce, key)
console.log('na', ctext.toString('hex'))


var input2 = new Buffer(input.length + 32)
input2.fill(0)
input.copy(input2, 32)
//input2.write(input, 32)
output = input2
cl.crypto_secretbox(output, input2, nonce, key)
console.log('cl', output.toString('hex'))

console.log('na', na.crypto_secretbox_open(ctext, nonce, key).toString('hex'))

var ptext = Z(input.length+32)
var ptext2 = output //Z(input.length+32)
cl.crypto_secretbox_open(ptext, output, nonce, key)
console.log('cl1', ptext.slice(32).toString('hex'))
cl.crypto_secretbox_open(ptext2, ctext, nonce, key)
console.log('cl2', ptext2.slice(32).toString('hex'))

//console.log(output.toString('hex'))

console.log(na.crypto_secretbox_open(output, nonce, key))

//console.log(hash(abc).toString('hex'))
//console.log(crypto.createHash('sha512').update(abc).digest().toString('hex'))

