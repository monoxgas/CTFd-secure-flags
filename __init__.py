import base64
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.flags import FLAG_CLASSES, CTFdRegexFlag, FlagException

BLOCK_SIZE = 16


class CTFdEncryptedRegexFlag(CTFdRegexFlag):
    name = "encrypted-regex"
    templates = {
        "create": "/plugins/CTFd-secure-flags/assets/encrypted-regex/create.html",
        "update": "/plugins/CTFd-secure-flags/assets/encrypted-regex/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        flag_regex = chal_key_obj.content
        aes_key = chal_key_obj.data

        if len(aes_key) != BLOCK_SIZE:
            raise FlagException("Key is misconfigured, contact an admin")

        if not provided.startswith("flag{") or not provided.endswith("}"):
            raise FlagException("Flag format is incorrect")

        try:
            flag = base64.b64decode(provided[5:-1])
            iv = flag[:BLOCK_SIZE]
            cipher = AES.new(aes_key.encode(), AES.MODE_CBC, iv)
            provided = unpad(cipher.decrypt(flag[BLOCK_SIZE:]), BLOCK_SIZE).decode()
        except Exception as e:
            raise FlagException("Flag decryption failed") from e

        try:
            res = re.match(flag_regex, provided, re.IGNORECASE)
        except re.error as e:
            raise FlagException("Regex parse error occured") from e

        return res and res.group() == provided


def load(app):
    FLAG_CLASSES["encrypted-regex"] = CTFdEncryptedRegexFlag
    register_plugin_assets_directory(
        app, base_path="/plugins/CTFd-secure-flags/assets/"
    )
