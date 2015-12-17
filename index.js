var na = require('./build/Release/nodetweetnacl')
var crypto = require('crypto')
exports.crypto_hash_sha256 = function (msg) {
  return crypto.createHash('sha256').update(msg).digest()
}
exports.crypto_hash = function (msg) {
  var b = new Buffer(64)
  na.crypto_hash(b, msg)
  return b
}

exports.crypto_secretbox_easy = function (msg, nonce, key) {
  var b = new Buffer(msg.length + 32)
  msg.copy(b, 32)
  na.crypto_secretbox(b, b, nonce, key)
  return b.slice(16)
}

exports.crypto_secretbox_open_easy = function (ctxt, nonce, key) {
  var b = new Buffer(ctxt.length + 16)
  ctxt.copy(b, 16)
  if(na.crypto_secretbox_open(b, b, nonce, key))
    return null
  return b.slice(32)
}

//BROKEN
exports.crypto_box_easy = function (msg, nonce, pk, sk) {
  var b = new Buffer(msg.length + 32)
  msg.copy(b, 32)
  na.crypto_box(b, b, nonce, pk, sk)
  return b.slice(16)
}

exports.crypto_box_open_easy = function (ctxt, nonce, pk, sk) {
  var b = new Buffer(ctxt.length + 16)
  ctxt.copy(b, 16)
  if(na.crypto_box_open(b, b, nonce, pk, sk))
    return null
  return b.slice(32)
}
//BROKEN
exports.crypto_auth = function (key, msg) {
  return crypto.createHmac('sha512', key).update(msg).digest()
}
//BROKEN
exports.crypto_auth_verify = function (key, msg) {
  return crypto.createHmac('sha512', key).update(msg).digest()
}

exports.crypto_scalarmult = function (pk, sk) {
  console.log('SCALARMULT', pk, sk)
  var b = new Buffer(32)
  na.crypto_scalarmult(b, pk, sk)
  return b
}


