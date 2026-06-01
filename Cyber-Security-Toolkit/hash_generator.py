import hashlib

def generate_md5(file_path):

    md5 = hashlib.md5()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            md5.update(chunk)

    return md5.hexdigest()


def generate_sha256(file_path):

    sha = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            sha.update(chunk)

    return sha.hexdigest()