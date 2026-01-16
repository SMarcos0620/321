import urllib.parse

import block_ciphers


def submit(text: str):
    begin = "userid=456;userdata="
    end = ";session-id=31337"
    return urllib.parse.quote(begin + text + end)


def main():
    print(submit("hello"))
    pass


if __name__ == "__main__":
    main()
