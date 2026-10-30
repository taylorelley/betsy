# Third-party licensing

Dependency metadata inspected from the locked Cargo graph. Grammar crates are MIT; Tree-sitter is MIT. SQLite is bundled through libsqlite3-sys (MIT metadata; upstream SQLite is public domain). Dependencies retain their own notices. No upstream source is vendored in this repository.

`data/weaknesses/` contains weakness catalogs copied from scorpius-cli (see its `PROVENANCE.md`). The MITRE CWE-derived `cwe_database.json` is used under the MITRE CWE Terms of Use; the required copyright designation and license are reproduced in `data/weaknesses/CWE_NOTICE.txt`.

The HTTP client used by `betsy analyze` is ureq 2.12.1 (MIT OR Apache-2.0) with rustls 0.23.46 (Apache-2.0 OR ISC OR MIT), ring 0.17.14 (Apache-2.0 AND ISC), rustls-webpki 0.103.16 (ISC), untrusted 0.9.0 (ISC), subtle 2.6.1 (BSD-3-Clause) and webpki-roots (CDLA-Permissive-2.0). It is only used when a network provider is selected.

## (MIT OR Apache-2.0) AND Unicode-3.0

unicode-ident 1.0.27

## Apache-2.0 OR MIT

equivalent 1.0.3, fastrand 2.5.0, indexmap 2.14.2, utf8parse 0.2.2

## Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT

linux-raw-sys 0.12.1, rustix 1.1.5

## MIT

generic-array 0.14.7, libsqlite3-sys 0.35.0, rusqlite 0.37.0, strsim 0.11.1, tree-sitter 0.25.10, tree-sitter-c 0.24.1, tree-sitter-cpp 0.23.4, tree-sitter-javascript 0.25.0, tree-sitter-language 0.1.9, tree-sitter-python 0.25.0, tree-sitter-rust 0.24.0, tree-sitter-typescript 0.23.2, zmij 1.0.23

## MIT OR Apache-2.0

anstream 1.0.0, anstyle 1.0.14, anstyle-parse 1.0.0, anstyle-query 1.1.5, anstyle-wincon 3.0.11, anyhow 1.0.104, bitflags 2.13.2, block-buffer 0.10.4, bstr 1.13.1, cc 1.10.0, cfg-if 1.0.5, clap 4.6.7, clap_builder 4.6.7, clap_derive 4.6.7, clap_lex 1.1.1, colorchoice 1.0.5, cpufeatures 0.2.17, crossbeam-deque 0.8.8, crossbeam-epoch 0.9.21, crossbeam-utils 0.8.23, crypto-common 0.1.7, digest 0.10.7, errno 0.3.14, find-msvc-tools 0.1.15, getrandom 0.4.3, hashbrown 0.15.5, hashbrown 0.17.1, hashlink 0.10.0, heck 0.5.0, is_terminal_polyfill 1.70.2, itoa 1.0.18, libc 0.2.191, log 0.4.34, once_cell 1.21.4, once_cell_polyfill 1.70.2, pkg-config 0.3.34, proc-macro2 1.0.107, quote 1.0.47, regex 1.13.1, regex-automata 0.4.18, regex-syntax 0.8.11, serde 1.0.229, serde_core 1.0.229, serde_derive 1.0.229, serde_json 1.0.154, sha2 0.10.9, shlex 2.0.1, smallvec 1.16.4, streaming-iterator 0.1.9, syn 3.0.9, tempfile 3.27.0, typenum 1.20.1, windows-link 0.2.1, windows-sys 0.61.2

## MIT OR Apache-2.0 OR LGPL-2.1-or-later

r-efi 6.0.0

## MIT/Apache-2.0

fallible-iterator 0.3.0, fallible-streaming-iterator 0.1.9, vcpkg 0.2.15, version_check 0.9.5

## Unlicense OR MIT

aho-corasick 1.1.5, globset 0.4.20, ignore 0.4.33, memchr 2.8.3, winapi-util 0.1.11

## Unlicense/MIT

same-file 1.0.6, walkdir 2.5.0

## Zlib

foldhash 0.1.5, foldhash 0.2.0
