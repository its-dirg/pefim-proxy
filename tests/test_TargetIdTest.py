import os
import unittest
from saml2.ident import IdentDB
from pefimproxy.util.targetid import TargetIdHandler


class TargetIdTestCase(unittest.TestCase):

    def setup_class(self):
        self.id = IdentDB({})
        self.sp_entity_id = "https://localhost:/sp.xml"
        sp_id = "urn:mace:umu.se:sp"
        self.nameid1_text = "abcd0001"
        self.nameid1 = self.id.persistent_nameid(self.nameid1_text, sp_id)

    def get_aes_128_key(self):
        return os.urandom(16)

    def get_aes_192_key(self):
        return os.urandom(24)

    def get_aes_256_key(self):
        return os.urandom(32)

    def test_create_tid2_json(self):
        tih = TargetIdHandler()
        tid1 = self.nameid1.text.strip()
        tid2_json = tih.tid2_json(tid1, self.sp_entity_id)
        tid2_dict = tih.tid2_dict(tid2_json)
        assert tid2_dict["tid1"] == self.nameid1_text, "Cannot verify tid1."
        assert tid2_dict["sp_entityid"] == self.sp_entity_id, "Cannot verify SP entity id."
        assert tid2_dict["uuid"] is not None and len(tid2_dict["uuid"]) > 0, "Cannot verify SP entity id."

    def test_hash_tid1(self):
        hash_verify = {'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64, 'sha384': 96, 'sha512': 128}
        try:
            TargetIdHandler(h_alg="do_not_exist_alg")
            assert False, "Must be an assert since the alg. do not exist."
        except:
            pass

        tih = TargetIdHandler()
        tid1 = self.nameid1.text.strip()
        tid2_hash = tih.tid2_hash(tid1, self.sp_entity_id)
        assert len(tid2_hash) == 64, "Default is sha256 alg and i should generate a string with length 64."

        for tmp_h_alg in hash_verify:
            tih = TargetIdHandler(h_alg=tmp_h_alg)
            tid1 = self.nameid1.text.strip()
            tid2_hash = tih.tid2_hash(tid1, self.sp_entity_id)
            assert len(tid2_hash) == hash_verify[tmp_h_alg], "%s alg should generate a string with length %d." % \
                                         (tmp_h_alg, hash_verify[tmp_h_alg])

    def test_encrypt_tid1(self):
        tih = TargetIdHandler()
        tid1 = self.nameid1.text.strip()
        tid2_encrypted = tih.tid2_encrypt(tid1, self.sp_entity_id)
        tid2_dict = tih.tid2_decrypt(tid2_encrypted)
        assert tid2_dict["tid1"] == self.nameid1_text, "Cannot verify tid1."
        assert tid2_dict["sp_entityid"] == self.sp_entity_id, "Cannot verify SP entity id."
        assert tid2_dict["uuid"] is not None and len(tid2_dict["uuid"]) > 0, "Cannot verify SP entity id."

    def test_encrypt_alg_1(self):
        for alg in TargetIdHandler.AES_ALG:
            typ, bits, cmode = alg.split("_")
            tih = TargetIdHandler(e_alg=alg)
            tid1 = self.nameid1.text.strip()
            tid2_encrypted = tih.tid2_encrypt(tid1, self.sp_entity_id)
            tid2_dict = tih.tid2_decrypt(tid2_encrypted)
            assert tid2_dict["tid1"] == self.nameid1_text, "Cannot verify tid1."
            assert tid2_dict["sp_entityid"] == self.sp_entity_id, "Cannot verify SP entity id."
            assert tid2_dict["uuid"] is not None and len(tid2_dict["uuid"]) > 0, "Cannot verify SP entity id."

    def test_encrypt_alg_2(self):
        for alg in TargetIdHandler.AES_ALG:
            typ, bits, cmode = alg.split("_")
            iv = os.urandom(16)
            key = os.urandom(int(bits) >> 3)
            tih = TargetIdHandler(e_alg=alg, iv=iv, key=key)
            tid1 = self.nameid1.text.strip()
            tid2_encrypted = tih.tid2_encrypt(tid1, self.sp_entity_id)
            tid2_dict = tih.tid2_decrypt(tid2_encrypted)
            assert tid2_dict["tid1"] == self.nameid1_text, "Cannot verify tid1."
            assert tid2_dict["sp_entityid"] == self.sp_entity_id, "Cannot verify SP entity id."
            assert tid2_dict["uuid"] is not None and len(tid2_dict["uuid"]) > 0, "Cannot verify uuid."

    def test_encrypt_alg_3(self):
        for alg in TargetIdHandler.AES_ALG:
            typ, bits, cmode = alg.split("_")
            iv = os.urandom(16)
            key = os.urandom(int(bits) >> 3)
            tih = TargetIdHandler(e_alg=alg, iv=iv, key=key)
            tid1 = self.nameid1.text.strip()
            tid2_encrypted_1 = tih.tid2_encrypt(tid1, self.sp_entity_id)
            tid2_encrypted_2 = tih.tid2_encrypt(tid1, self.sp_entity_id)
            tid2_dict_1 = tih.tid2_decrypt(tid2_encrypted_1)
            tid2_dict_2 = tih.tid2_decrypt(tid2_encrypted_2)
            assert tid2_encrypted_1 != tid2_encrypted_2, "Two encryption of the same data must never be the same!"
            assert tid2_dict_1["tid1"] == tid2_dict_2["tid1"] == self.nameid1_text, "Cannot verify tid1."
            assert tid2_dict_1["sp_entityid"] == tid2_dict_2["sp_entityid"] == self.sp_entity_id, \
                "Cannot verify SP entity id."
            assert tid2_dict_1["uuid"] != tid2_dict_2["uuid"], "Cannot verify uuid."

    def test_encrypt_alg_4(self):
        for alg in TargetIdHandler.AES_ALG:
            typ, bits, cmode = alg.split("_")
            iv = os.urandom(16)
            key = os.urandom(int(bits) >> 3)
            tih = TargetIdHandler(e_alg=alg, iv=iv, key=key)
            tid1 = self.nameid1.text.strip()
            iv = tih.get_new_iv()
            tid2_encrypted_1 = tih.tid2_encrypt(tid1, self.sp_entity_id, iv=iv)
            tid2_encrypted_2 = tih.tid2_encrypt(tid1, self.sp_entity_id, iv=iv)
            tid2_dict_1 = tih.tid2_decrypt(tid2_encrypted_1)
            tid2_dict_2 = tih.tid2_decrypt(tid2_encrypted_2)
            assert tid2_encrypted_1 != tid2_encrypted_2, "Two encryption of the same data must never be the same!"
            assert tid2_dict_1["tid1"] == tid2_dict_2["tid1"] == self.nameid1_text, "Cannot verify tid1."
            assert tid2_dict_1["sp_entityid"] == tid2_dict_2["sp_entityid"] == self.sp_entity_id, \
                "Cannot verify SP entity id."
            assert tid2_dict_1["uuid"] != tid2_dict_2["uuid"], "Cannot verify uuid."