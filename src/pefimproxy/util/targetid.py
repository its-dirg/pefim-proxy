import json
import os
from uuid import uuid4
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from saml2.aes import AESCipher


class TargetIdHandler(object):
    AES_ALG = ["aes_128_cbc", "aes_128_cfb", "aes_128_ecb",
               "aes_192_cbc", "aes_192_cfb", "aes_192_ecb",
               "aes_256_cbc", "aes_256_cfb", "aes_256_ecb"]

    def __init__(self, e_alg=None, key=None, h_alg=None, iv=None):

        if e_alg is None:
            self.e_alg = self.AES_ALG[0]
        else:
            self.e_alg = e_alg
        assert self.e_alg in self.AES_ALG, "The encryption alg %s do not exist. Use one of the follwing encryption " \
                                            "alg: %s" % (self.alg, self.AES_ALG)
        typ, bits, cmode = self.e_alg.split("_")
        if key is None:
            self.key = os.urandom(int(bits) >> 3)
        else:
            self.key = key
        assert len(self.key) == int(bits) >> 3, "The key must consist of %d bytes." % int(bits) >> 3
        if h_alg is None:
            self.h_alg = "sha256"
        else:
            self.h_alg = h_alg
        if iv is None:
            self.iv = Random.new().read(AES.block_size)
        else:
            self.iv = iv
        assert len(self.iv) == AES.block_size, "The initialization vector must be %d size." % AES.block_size
        h_alg_ok = False
        approved_hash_alg = ""
        for tmp_h_alg in hashlib.algorithms:
            if self.h_alg == tmp_h_alg:
                h_alg_ok = True
            approved_hash_alg += tmp_h_alg + ","
        assert h_alg_ok, "The hash alg %s do not exist. Use one of the following alg: %s" % (self.h_alg,
                                                                                             approved_hash_alg)
        self.aes = AESCipher(key=self.key, iv=self.iv)

    def get_new_iv(self):
        return Random.new().read(AES.block_size)

    def td2_json(self, tid1, sp_entityid):
        td2_dict = {
            "tid1": tid1,
            "sp_entityid": sp_entityid,
            "uuid": uuid4().urn
        }
        return json.dumps(td2_dict)

    def td2_dict(self, tid2_json):
        return json.loads(tid2_json)

    def td2_encrypt(self, tid1, sp_entityid, iv=None):
        td2 = self.td2_json(tid1, sp_entityid)
        td2_encrypt = self.aes.encrypt(msg=td2, alg=self.e_alg, iv=None)
        return td2_encrypt

    def td2_decrypt(self, td2_encrypted, iv=None):
        td2_json = self.aes.decrypt(td2_encrypted, alg=self.e_alg, iv=None)
        return self.td2_dict(td2_json)

    def td2_hash(self, tid1, sp_entityid):
        td2 = self.td2_json(tid1, sp_entityid)
        hash_func = getattr(hashlib, self.h_alg)
        return hash_func(td2).hexdigest()

    def uid_hash(self, tid1):
        hash_func = getattr(hashlib, self.h_alg)
        return hash_func(tid1).hexdigest()