#!/usr/bin/env python3
"""
balance_flows.py

Create a balanced CSV with 50% Normal / 50% Malicious flows from an existing flows CSV.

Usage:
  python3 balance_flows.py --in flows.csv --out flows_balanced.csv

Options:
  --method {downsample,upsample}  How to get equal class sizes. Default: downsample
  --per-class N                   Number of rows per class (overrides automatic choice)
  --label-col NAME                Column name containing labels (default: 'label')
  --seed N                        RNG seed for reproducible sampling

By default the script downsamples the larger class to match the smaller class.
"""
import argparse
import csv
import random
import sys


def balance(rows, label_col='label', method='downsample', per_class=None, seed=None):
    # rows: list of dicts
    labels = {}
    for r in rows:
        lab = r.get(label_col)
        labels.setdefault(lab, []).append(r)

    if 'Normal' not in labels or 'Malicious' not in labels:
        raise ValueError("Both 'Normal' and 'Malicious' labels must be present in the input CSV")

    a = labels['Normal']
    b = labels['Malicious']
    na = len(a); nb = len(b)

    if per_class is None:
        if method == 'downsample':
            per = min(na, nb)
        elif method == 'upsample':
            per = max(na, nb)
        else:
            raise ValueError('method must be downsample or upsample')
    else:
        per = int(per_class)

    rng = random.Random(seed)

    def sample_list(lst, n, replace=False):
        if not replace and n > len(lst):
            # fallback to sampling with replacement if asked sample larger than available
            replace = True
        if replace:
            return [rng.choice(lst) for _ in range(n)]
        return rng.sample(lst, n)

    if method == 'downsample':
        a_samp = sample_list(a, per, replace=False)
        b_samp = sample_list(b, per, replace=False)
    else:
        a_samp = sample_list(a, per, replace=(per>len(a)))
        b_samp = sample_list(b, per, replace=(per>len(b)))

    out = a_samp + b_samp
    rng.shuffle(out)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='infile', required=True, help='Input flows CSV')
    ap.add_argument('--out', dest='outfile', required=True, help='Output balanced CSV')
    ap.add_argument('--method', choices=('downsample', 'upsample'), default='downsample')
    ap.add_argument('--per-class', dest='per_class', type=int, default=None)
    ap.add_argument('--label-col', dest='label_col', default='label')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    # read csv with csv module to avoid pandas dependency
    with open(args.infile, newline='') as fh:
        rdr = csv.DictReader(fh)
        rows = list(rdr)

    balanced = balance(rows, label_col=args.label_col, method=args.method, per_class=args.per_class, seed=args.seed)

    # write out
    if len(balanced) == 0:
        print('No rows to write', file=sys.stderr); sys.exit(1)
    fieldnames = list(balanced[0].keys())
    with open(args.outfile, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(balanced)

    # counts
    from collections import Counter
    counts = Counter(r[args.label_col] for r in balanced)
    print(f"Wrote {len(balanced)} rows to {args.outfile}")
    print("Counts:", dict(counts))


if __name__ == '__main__':
    main()
