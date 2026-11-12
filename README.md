# nmap-parser

Turns messy nmap and gobuster output into a clean per-host summary.

Feed it nmap scans and gobuster results, and it shows open ports and found web paths for each host in one place.
It also warns you if something looks wrong, like a scan that was cut off.

```
$ ./recon-parser-util.py scan.txt gobuster.txt

========================================================================
TARGET  10.10.10.5 (box.htb)  [UP]
------------------------------------------------------------------------
  PORT      STATE  SERVICE   VERSION
  22/tcp    open   ssh       OpenSSH 8.2p1 Ubuntu
  80/tcp    open   http      Apache httpd 2.4.41 ((Ubuntu))

  WEB CONTENT (gobuster)
  TYPE  STATUS  SIZE   URL
  dir   301     308    http://box.htb/admin  -> http://box.htb/admin/
  dir   200     11321  http://box.htb/index.php

========================================================================
Summary: 1 host(s), 1 up, 2 open port(s), 2 web finding(s), 0 warning(s)
```

## Install

You only need Python 3.

```bash
git clone https://github.com/9ineIX/nmap-parser.git
cd nmap-parser
chmod +x recon-parser-util.py
```

Run it from the project folder with `./` in front: `./recon-parser-util.py`.

Want to run it from anywhere as just `recon-parser`? Make a link once:

```bash
sudo ln -s "$PWD/recon-parser-util.py" /usr/local/bin/recon-parser
```

Then `nmap -sV 10.10.10.5 | recon-parser` works in any folder.

## Usage

Pipe nmap straight into it:

```bash
nmap -sV 10.10.10.5 | ./recon-parser-util.py
```

Or pass saved files. You don't have to say which file is which, it figures that out itself:

```bash
./recon-parser-util.py scan.txt gobuster.txt
```

It understands:
- nmap normal output, `-oX` and `-oG`
- gobuster `dir`, `dns` and `vhost`

## Scan everything with one command

`recon.sh` runs nmap for you, then gobuster on every web port it finds, and shows one summary at the end:

```bash
./recon.sh 10.10.10.5
```

Everything is saved in a folder named after the target: raw nmap and gobuster output plus `report.md`.

By default nmap runs with `-sV -sC` and gobuster uses `common.txt`. You can change both:

```bash
./recon.sh box.htb -n "-p- -sV -sC" -w /usr/share/seclists/Discovery/Web-Content/big.txt
./recon.sh 10.10.10.5 -G        # nmap only, skip gobuster
```

Run `./recon.sh -h` for all options.

## Handy options

```bash
./recon-parser-util.py scan.txt --state all           # show closed/filtered ports too
./recon-parser-util.py scan.txt --scripts             # show nmap script output (-sC)
./recon-parser-util.py scan.txt gob.txt --status 200  # only show some gobuster codes
./recon-parser-util.py scan.txt -f md -o notes.md     # save as Markdown for notes
./recon-parser-util.py scan.txt -f json               # JSON for scripts
```

Find every web server in a scan and run gobuster on each one:

```bash
./recon-parser-util.py scan.txt -f urls | xargs -I{} gobuster dir -u {} -w wordlist.txt
```

If you saved gobuster with `-o`, the file doesn't contain the target URL.
Pass it with `-u` so the results land under the right host:

```bash
./recon-parser-util.py scan.txt gob.txt -u http://10.10.10.5
```

Run `./recon-parser-util.py -h` to see every option.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Note

Only scan machines you own or are allowed to test.
