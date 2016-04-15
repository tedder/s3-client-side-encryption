#!/usr/bin/env python3

# Copyright 2015, MIT license, github.com/tedder42.
# You know what the MIT license is, follow it.

# todo:
# - encrypt and "stream" file to s3/boto3, no intermediate file.
# - ensure python2 compatability (if anyone cares)
# - integrate into boto3

import base64
import json
from Crypto.Cipher import AES # pycryptodome
from Crypto import Random
import boto3
import struct
import sys
import os

if len(sys.argv) != 5:
  print("usage: put.py local_file bucket s3_key kms_arn")
  sys.exit(-1)

infile = sys.argv[1]
bucket_name = sys.argv[2]
key_name = sys.argv[3]
kms_arn = sys.argv[4]

# generating this "encrypt and put" code by:
# (a) reversing the decrypt, which I know works
# (b) black-boxing output (metadata) to match the Java SDK
# (c) using this: https://github.com/aws/aws-sdk-ruby/blob/master/aws-sdk-resources/lib/aws-sdk-resources/services/s3/encryption/kms_cipher_provider.rb#L16

# decrypt_file method from: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# via: https://github.com/boto/boto3/issues/38#issuecomment-174106849
def encrypt_file(key, in_filename, iv, original_size, out_filename, chunksize=16*1024):
    with open(in_filename, 'rb') as infile:
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # 3 cases here for padding at the end of file:
        # - we get a full chunk of 16. pass it through.
        # - we get a partial chunk at EOF. we pad it up to 16. generally speaking each byte is the byte number, so if we have 7 bytes, the following nine are "07 07 07 07 07 07 07 07 07".
        # - we get a zero-byte chunk at EOF. This means the file was a perfect multiple of 16, but padding means the end of the file should be padded because IDK why but that's how it's done. See url below:
        #
        # the extra padding at zero-byte EOF: http://security.stackexchange.com/a/29997
        #   "The above problem is solved by knowing that you always pad your data, no matter the length."
        with open(out_filename, 'wb') as outfile:
            last_chunk_length = 0
            while True:
                chunk = infile.read(chunksize)
                last_chunk_length = len(chunk)
                if last_chunk_length == 0 or last_chunk_length < chunksize:
                  break
                outfile.write(cipher.encrypt(chunk))

            # write the final padding
            length_to_pad = 16 - (last_chunk_length % 16)
            # not py2 compatible
            # chunk += bytes([length])*length
            chunk += struct.pack('B', length_to_pad) * length_to_pad
            outfile.write(cipher.encrypt(chunk))


def put_file(ciphertext_blob, new_iv, encrypt_ctx, upload_filename, unencrypted_file_size, bucket_name, key_name):

    matdesc_string = json.dumps(encrypt_ctx)
    metadata = {
        'x-amz-key-v2': base64.b64encode(ciphertext_blob).decode('utf-8'),
        'x-amz-iv': base64.b64encode(new_iv).decode('utf-8'),
        'x-amz-cek-alg': 'AES/CBC/PKCS5Padding',
        'x-amz-wrap-alg': 'kms',
        'x-amz-matdesc': matdesc_string,
        'x-amz-unencrypted-content-length': str(unencrypted_file_size)
    }

    s3client = boto3.client('s3')
    s3transfer = boto3.s3.transfer.S3Transfer(s3client)
    s3transfer.upload_file(upload_filename, bucket_name, key_name, extra_args={'Metadata': metadata})

# s3_encryption reads everything into memory. we can avoid this if we add chunking (and file 'handles') to s3_encryption:
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#highlighter_842384
# http://legrandin.github.io/pycryptodome/Doc/3.3.1/Crypto.Cipher._mode_cbc.CbcMode-class.html
# https://github.com/boldfield/s3-encryption/blob/08f544f06e7f86d5df978718d6b3958c2eebba6a/s3_encryption/handler.py#L39

s3 = boto3.client('s3')
location_info = s3.get_bucket_location(Bucket=bucket_name)
bucket_region = location_info['LocationConstraint']

kms = boto3.client('kms')
encrypt_ctx = {"kms_cmk_id":kms_arn}

key_data = kms.generate_data_key(KeyId=kms_arn, EncryptionContext=encrypt_ctx, KeySpec="AES_256")
new_iv = Random.new().read(AES.block_size)
size_infile = os.stat(infile).st_size # unencrypted length
outfile = infile + '.enc'

encrypt_file(key_data['Plaintext'], infile, new_iv, size_infile, outfile, chunksize=16*1024)
put_file(key_data['CiphertextBlob'], new_iv, encrypt_ctx, outfile, size_infile, bucket_name, key_name)

