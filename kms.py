#!/usr/bin/env python
# Copyright 2015 Luminal, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class KeyService(object):

    def __init__(self, kms, key_id, encryption_context):
        self.kms = kms
        self.key_id = key_id
        self.encryption_context = encryption_context

    def generate_key_data(self, number_of_bytes):
        try:
            kms_response = self.kms.generate_data_key(
                KeyId=self.key_id, EncryptionContext=self.encryption_context, NumberOfBytes=number_of_bytes
            )
        except Exception as e:
            raise KmsError("Could not generate key using KMS key %s (Detail: %s)" % (self.key_id, e.message))
        return kms_response['Plaintext'], kms_response['CiphertextBlob']

    def decrypt(self, encoded_key):
        try:
            kms_response = self.kms.decrypt(
                CiphertextBlob=encoded_key,
                EncryptionContext=self.encryption_context
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidCiphertextException":
                if self.encryption_context is None:
                    msg = ("Could not decrypt hmac key with KMS. The credential may "
                           "require that an encryption context be provided to decrypt "
                           "it.")
                else:
                    msg = ("Could not decrypt hmac key with KMS. The encryption "
                           "context provided may not match the one used when the "
                           "credential was stored.")
            else:
                msg = "Decryption error %s" % e
            raise KmsError(msg)
        return kms_response['Plaintext']


class KmsError(Exception):

    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"

    def __str__(self):
        return self.value
