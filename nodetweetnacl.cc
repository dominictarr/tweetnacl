#include <node.h>
#include <node_buffer.h>

#include <cstdlib>
#include <ctime>
#include <cstring>
#include <string>
#include <sstream>

#include <nan.h>

extern "C" {
  //this magic extern "C" is required
  //to ward off the EVIL EYE of the MANGLER
  #include "tweetnacl.h"
}

using namespace node;
using namespace v8;

// get handle to the global object
Local<Object> globalObj = Nan::GetCurrentContext()->Global();

// Retrieve the buffer constructor function
Local<Function> bufferConstructor =
       Local<Function>::Cast(globalObj->Get(Nan::New<String>("Buffer").ToLocalChecked()));


// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i,msg) \
    if (!Buffer::HasInstance(info[i])) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be a buffer"; \
        return Nan::ThrowError(oss.str().c_str()); \
    }

// Create a new buffer, and get a pointer to it
#define NEW_BUFFER_AND_PTR(name, size) \
    Local<Object> name = Nan::NewBuffer(size).ToLocalChecked(); \
    unsigned char* name ## _ptr = (unsigned char*)Buffer::Data(name)

#define GET_ARG_AS(i, NAME, TYPE) \
    ARG_IS_BUFFER(i,#NAME); \
    TYPE NAME = (TYPE) Buffer::Data(info[i]->ToObject()); \
    unsigned long long NAME ## _size = Buffer::Length(info[i]->ToObject()); \
    if( NAME ## _size == 0 ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " length cannot be zero" ; \
        return Nan::ThrowError(oss.str().c_str()); \
    }

#define GET_ARG_AS_LEN(i, NAME, MAXLEN, TYPE) \
    GET_ARG_AS(i, NAME, TYPE); \
    if( NAME ## _size != MAXLEN ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long" ; \
        return Nan::ThrowError(oss.str().c_str()); \
    }

#define GET_ARG_AS_UCHAR(i, NAME) \
    GET_ARG_AS(i, NAME, unsigned char*)

#define GET_ARG_AS_UCHAR_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, unsigned char*)

#define GET_ARG_AS_VOID(i, NAME) \
    GET_ARG_AS(i, NAME, void*)

#define GET_ARG_AS_VOID_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, void*)


#define NUMBER_OF_MANDATORY_ARGS(n, message) \
    if (info.Length() < (n)) {               \
        return Nan::ThrowError(message);       \
    }

#define TO_REAL_BUFFER(slowBuffer, actualBuffer) \
    Handle<Value> constructorArgs ## slowBuffer[3] = \
        { slowBuffer->handle_, \
          Nan::New<Integer>(Buffer::Length(slowBuffer)), \
          Nan::New<Integer>(0) }; \
    Local<Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs ## slowBuffer);



/**
 * int crypto_hash(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */

#define RETURN(val) \
  info.GetReturnValue().Set(val)

NAN_METHOD(bind_crypto_hash) {
    Nan::EscapableHandleScope scope;
    NUMBER_OF_MANDATORY_ARGS(2,"argument message must be a buffer");
    GET_ARG_AS_UCHAR(0,hash_ptr);
    GET_ARG_AS_UCHAR(1,msg);
    RETURN(crypto_hash_sha512_tweet(hash_ptr, msg, msg_size));
}

//don't know what is going on here...
NAN_METHOD(bind_crypto_secretbox) {
    Nan::EscapableHandleScope scope;
    NUMBER_OF_MANDATORY_ARGS(2,"argument message must be a buffer");
    GET_ARG_AS_UCHAR(0, ctext);
    GET_ARG_AS_UCHAR(1, ptext);
    GET_ARG_AS_UCHAR_LEN(2, nonce, crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(3, key, crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES);

    RETURN(crypto_secretbox_xsalsa20poly1305(ctext, ptext, ptext_size, nonce, key));
}

NAN_METHOD(bind_crypto_secretbox_open) {
    Nan::EscapableHandleScope scope;
    NUMBER_OF_MANDATORY_ARGS(2,"argument message must be a buffer");
    GET_ARG_AS_UCHAR(0, ptext);
    GET_ARG_AS_UCHAR(1, ctext);
    GET_ARG_AS_UCHAR_LEN(2, nonce, crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(3, key, crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES);

    RETURN(crypto_secretbox_xsalsa20poly1305(ptext, ctext, ctext_size, nonce, key));
}
#define NEW_INT_PROP(NAME) \
    Nan::ForceSet(target, Nan::New<String>(#NAME).ToLocalChecked(), Nan::New<Integer>(NAME), v8::ReadOnly);

#define NEW_STRING_PROP(NAME) \
    Nan::ForceSet(target, Nan::New<String>(#NAME).ToLocalChecked(), Nan::New<String>(NAME).ToLocalChecked(), v8::ReadOnly);

#define NEW_METHOD(NAME) \
    Nan::SetMethod(target, #NAME, bind_ ## NAME)

void RegisterModule(Handle<Object> target) {

    // Hash
    NEW_METHOD(crypto_hash);
    NEW_METHOD(crypto_secretbox);
    NEW_METHOD(crypto_secretbox_open);

}

NODE_MODULE(nodetweetnacl, RegisterModule);

