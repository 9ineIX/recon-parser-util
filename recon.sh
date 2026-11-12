#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<EOF
usage: ./recon.sh TARGET [options]

Runs nmap on TARGET, then gobuster on every web port it finds,
and shows everything as one summary.

options:
  -n ARGS   nmap flags (default: "-sV -sC")
  -w FILE   gobuster wordlist
  -t NUM    gobuster threads (default: 20)
  -o DIR    where to save results (default: ./TARGET)
  -G        skip gobuster
  -h        show this help

examples:
  ./recon.sh 10.10.10.5
  ./recon.sh box.htb -n "-p- -sV -sC" -w /usr/share/seclists/Discovery/Web-Content/big.txt
EOF
}

target=""
nmap_args="-sV -sC"
wordlist=""
threads=20
outdir=""
skip_gobuster=false

if [[ $# -gt 0 && $1 != -* ]]; then
    target=$1
    shift
fi

while getopts "n:w:t:o:Gh" opt; do
    case $opt in
        n) nmap_args=$OPTARG ;;
        w) wordlist=$OPTARG ;;
        t) threads=$OPTARG ;;
        o) outdir=$OPTARG ;;
        G) skip_gobuster=true ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

[[ -z $target && $# -gt 0 ]] && target=$1
if [[ -z $target ]]; then
    usage
    exit 2
fi

parser="$(dirname "$(readlink -f "$0")")/recon-parser-util.py"
outdir=${outdir:-$target}

if ! command -v nmap >/dev/null; then
    echo "[!] nmap is not installed" >&2
    exit 1
fi

if ! $skip_gobuster; then
    if ! command -v gobuster >/dev/null; then
        echo "[!] gobuster is not installed, skipping it (use -G to hide this message)" >&2
        skip_gobuster=true
    elif [[ -z $wordlist ]]; then
        for f in /usr/share/seclists/Discovery/Web-Content/common.txt \
                 /usr/share/wordlists/dirb/common.txt \
                 /usr/share/dirb/wordlists/common.txt; do
            if [[ -f $f ]]; then
                wordlist=$f
                break
            fi
        done
    fi
    if ! $skip_gobuster && [[ ! -f $wordlist ]]; then
        echo "[!] wordlist not found, pass one with -w (or skip gobuster with -G)" >&2
        exit 1
    fi
fi

mkdir -p "$outdir"

echo "[*] nmap $nmap_args $target"
# shellcheck disable=SC2086
nmap $nmap_args -oA "$outdir/nmap" "$target" || { echo "[!] nmap failed" >&2; exit 1; }

if ! $skip_gobuster; then
    mapfile -t urls < <("$parser" "$outdir/nmap.xml" -f urls -q)
    if [[ ${#urls[@]} -eq 0 ]]; then
        echo "[*] no web ports found, skipping gobuster"
    fi
    for url in "${urls[@]}"; do
        name=$(sed 's#^https\?://##; s#[^A-Za-z0-9.-]#_#g' <<< "$url")
        out="$outdir/gobuster_$name.txt"
        echo
        echo "[*] gobuster $url"
        { echo "[+] Url: $url"
          gobuster dir -u "$url" -w "$wordlist" -t "$threads" -k -q --no-progress
        } | tee "$out" || echo "[!] gobuster failed for $url" >&2
        if [[ $(wc -l < "$out") -le 1 ]]; then
            rm -f "$out"
        fi
    done
fi

shopt -s nullglob
files=("$outdir/nmap.xml" "$outdir"/gobuster_*.txt)

echo
"$parser" "${files[@]}"
"$parser" "${files[@]}" -q -f md -o "$outdir/report.md"
echo
echo "[*] results saved to $outdir/ (report: $outdir/report.md)"
