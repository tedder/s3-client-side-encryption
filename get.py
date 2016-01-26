#!/usr/bin/env python3

# Copyright 2015, MIT license, github.com/tedder42.
# You know what the MIT license is, follow it.

# todo:
# - decrypt while "streaming" from s3/boto3, no intermediate file (and no hardcoded "decrypted-" filename)
# - ensure python2 compatability (if anyone cares)
# - integrate into boto3

import base64
import json
from Crypto.Cipher import AES # pycryptodome
import boto3
import sys

if len(sys.argv) != 4:
  print("usage: get.py bucket s3_key destination_filename")
  sys.exit(-1)

bucket_name = sys.argv[1]
key_name = sys.argv[2]
dest_file = sys.argv[3]

# decrypt_file method from: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# via: https://github.com/boto/boto3/issues/38#issuecomment-174106849
def decrypt_file(key, in_filename, iv, original_size, out_filename, chunksize=16*1024):
    with open(in_filename, 'rb') as infile:
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(original_size)

# s3_encryption reads everything into memory. we can avoid this if we add chunking (and file 'handles') to s3_encryption:
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#highlighter_842384
# http://legrandin.github.io/pycryptodome/Doc/3.3.1/Crypto.Cipher._mode_cbc.CbcMode-class.html
# https://github.com/boldfield/s3-encryption/blob/08f544f06e7f86d5df978718d6b3958c2eebba6a/s3_encryption/handler.py#L39

s3 = boto3.client('s3')
location_info = s3.get_bucket_location(Bucket=bucket_name)
bucket_region = location_info['LocationConstraint']
object_info = s3.head_object(Bucket=bucket_name, Key=key_name)

metadata = object_info['Metadata']
material_json = object_info['Metadata']['x-amz-matdesc']
# material_json is a string of json. Yes, json inside json.

envelope_key = base64.b64decode(metadata['x-amz-key-v2'])
envelope_iv = base64.b64decode(metadata['x-amz-iv'])
encrypt_ctx = json.loads(metadata['x-amz-matdesc'])
original_size = metadata['x-amz-unencrypted-content-length']

kms = boto3.client('kms')
decrypted_envelope_key = kms.decrypt(CiphertextBlob=envelope_key,EncryptionContext=encrypt_ctx)

s3.download_file(bucket_name, key_name, dest_file)
decrypt_file(decrypted_envelope_key['Plaintext'], dest_file, envelope_iv, int(original_size), "decrypted-" + dest_file)

