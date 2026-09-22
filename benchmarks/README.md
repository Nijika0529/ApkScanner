# Benchmarks

## `asc_xref_bench.py` — is the optional ASC xref integration worth it?

The platform's attack-chain graph builds app-class adjacency by regexing
decompiled Java/Smali inside a bounded node/byte budget
(`AndroidAttackChainAnalyzer._build_adjacency`). ASC (`droidasc`) answers the same
inbound-reference question from the DEX directly. This benchmark uses ASC as the
fact baseline and reports, per APK:

| column | meaning |
| --- | --- |
| `ASC refs` | hits for the fixed framework-type + string query set |
| `ASC s` / `ASC MB` | wall time and peak RSS of one ASC extraction |
| `decompile` / `dec s` | decompiler used for the regex path and its wall time |
| `nodes` | app classes the bounded regex index considered |
| `app targets` | sampled app-class targets that had at least one ASC edge |
| `recall` | ASC-confirmed referencing classes the regex graph finds |
| `precision` | regex edges ASC confirms (1 - fabrication) |
| `fabricated` | regex edges ASC does not confirm |

`recall`/`precision` are restricted to **app-owned classes and app-class
targets**, because that is the only edge set the regex adjacency models. The fixed
`ASC refs` set (framework types and strings) is a *capture* metric: the regex
graph cannot represent those references at all.

### Run

```bash
# Fast path: ASC only (no decompiler needed)
python benchmarks/asc_xref_bench.py \
    --apk /path/one.apk --apk /path/two.apk \
    --out benchmarks/results

# With the regex comparison (needs apktool or jadx)
python benchmarks/asc_xref_bench.py \
    --apk /path/one.apk --decompile apktool \
    --out benchmarks/results
```

Requires the optional dependency and a JDK-backed decompiler for `--decompile`:

```bash
pip install -e '.[asc]'
```

Outputs `asc_xref_bench.md` and `asc_xref_bench.json` under `--out`. Decompiled
trees are written to `<out>/work/` and are not part of the repository.

### Notes

* APKs are not committed; point `--apk` at local files.
* In-process (library) transport does not use `multiprocessing`, so it also works
  in restricted containers where the `droidasc findrefs` CLI cannot start a
  process pool.
* Peak RSS is dominated by the largest single `classes*.dex` index, because the
  extraction streams one DEX at a time.
