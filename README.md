# SDSSE – Dynamic Searchable Conjunctive Symmetric Encryption Suite

SDSSE is a C++23 implementation of Conjunctive Searchable Symmetric Encryption (SSE) constructions.

> [!WARNING]
> This is a research prototype – API & on-disk formats may change without notice.

## Features

- **Forward & Backward Privacy:** Implements schemes ensuring privacy even against adaptive adversaries.
  - TEDB: For single-keyword searches.
  - XEDB: For conjunctive (multi-keyword) searches.
- **Complete SDSSECQS Scheme:** Combines TEDB and XEDB for a comprehensive dynamic SSE solution.
- **High-Performance Server:** A standalone server (`SSEServerStandalone`) capable of handling multiple client connections and databases.
- **Lightweight Client:** The `SDSSECQSClient` provides a C++ API for applications to integrate SSE capabilities.
- **Command-Line Tool:** `SDSSECQSCLI` for easy indexing, deletion, and searching directly from the terminal.
- **Benchmarking Suite:** Includes micro-benchmarks for individual components (SM4, Bloom Filter, GGM tree) and end-to-end evaluation programs.

## Quick Start

1. **Clone the repository (including submodules):**

   ```bash
   git clone --recursive https://github.com/mix-archive/SDSSE.git
   cd SDSSE
   ```

2. **Build in Release mode:**

   ```bash
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(nproc)
   ```

3. **Start the SSE server (default port 5000):**

   ```bash
   ./build/bin/SSEServerStandalone &
   ```

4. **Use the CLI (from the `Data/` directory):**
   The CLI expects `pairing.param` & `elliptic_g` (Pairing-Based Cryptography parameters) to be in the current working directory.

   ```bash
   cd Data                        # Switch working directory so EC params are found
   ../build/bin/SDSSECQSCLI index 1984.txt
   ../build/bin/SDSSECQSCLI search 1984.txt big brother
   ```

   > The provided `Data/1984.txt` (a tokenized version of Orwell's "1984") already follows the expected format: `id<TAB>tokenised text…`. The first _tab-separated_ field is a numeric ID.

## Building from Source

The project uses CMake (≥ 3.17) and includes a `vcpkg` manifest (`vcpkg.json`) to manage dependencies. `vcpkg` will automatically fetch and build libraries like OpenSSL, msgpack-c, and args. GMP and PBC libraries are typically expected from the system or can also be managed by vcpkg depending on your setup.

### Prerequisites

- A C++23-compliant compiler (e.g., GCC 13+, Clang 16+, MSVC 19.36+).
- CMake (≥ 3.17).
- Ninja (recommended for faster builds).
- Git.

### Native Build (Linux)

```bash
# If you didn't clone with --recursive:
git submodule update --init --recursive

# Configure (CMake will use vcpkg toolchain file automatically)
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release

# Compile
cmake --build build -j$(nproc)

# Install binaries (e.g., into ./dist/bin)
cmake --install build --prefix dist
```

### Docker Build

A `Dockerfile` is provided for a reproducible build portable binaries.

```bash
docker build . --target output --output ./dist
```

The resulting distribution is minimal, containing only the necessary binaries and sample data.

## Usage

### Running the Server

The `SSEServerStandalone` executable starts a TCP server.

```bash
./build/bin/SSEServerStandalone
# Server listens on 0.0.0.0:5000 by default
```

- **Communication:** The server uses a length-prefixed MessagePack protocol.
- **Multi-Database:** Supports multiple logical databases per client connection, identified by a `db` field in requests (defaults to `"default"`).
- **Logging:** Provides timestamped logs for connections, handler initializations, and operations.

#### Example Server Output

```
[2025-05-11 06:53:27.083] SSE Server listening on port 5000
[2025-05-11 06:53:43.149] [db:tedb] Handler (re)initialised with GGM_SIZE 199355
[2025-05-11 06:53:43.150] [db:xedb] Handler (re)initialised with GGM_SIZE 199355
[2025-05-11 06:54:03.325] add_entries_batch (8192 items) took 42 ms
[2025-05-11 06:56:13.191] add_entries_batch (8192 items) took 64 ms
[2025-05-11 07:00:11.820] search took 175 ms
```

These lines illustrate server startup, initialization of TEDB/XEDB handlers for different databases, batch data additions, and search operations.

### Command-Line Interface (CLI)

The `SDSSECQSCLI` tool provides a convenient way to interact with the SSE functionalities.

> [!NOTE]
> Run `SDSSECQSCLI` from the `Data/` directory, as it loads `pairing.param` and `elliptic_g` using relative paths.

#### Commands Overview

```
SDSSECQSCLI COMMAND {OPTIONS}

Searchable encryption for conjunctive queries

OPTIONS:

    subcommands
    index                             index the file
    delete                            delete the file
    search                            search the file
    -h, --help                          Display this help menu
    "--" can be used to terminate flag options and force all following
    arguments to be treated as positional options
```

#### Examples

```bash
# Ensure you are in the Data directory
cd Data

# Build encrypted indexes from 1984.txt
../build/bin/SDSSECQSCLI index 1984.txt

# Remove entries associated with document ID 123
../build/bin/SDSSECQSCLI delete 1984.txt 123

# Query for documents containing BOTH "big" AND "brother"
../build/bin/SDSSECQSCLI search 1984.txt big brother
```

#### Sample Search Output

This is a sample output if you run the search command with the provided `1984.txt` file:

<!-- markdownlint-disable MD033 -->

<pre>
9498 keywords found in file.
14: <b>big brother</b> is watching you the caption beneath it ran
25: <b>big brother</b> is watching you the caption said while the dark eyes looked deep into winstons own
189: he was abusing <b>big brother</b> he was denouncing the dictatorship of the party...
...
6690: he loved <b>big brother</b>
</pre>

The CLI first loads keyword counts from the specified file to generate search tokens correctly.

## Implementation Details

This project implements dynamic searchable symmetric encryption schemes with a focus on forward and backward privacy. The core conjunctive search scheme, referred to as **SDSSE-CQ** in the accompanying research, builds upon the **OXT (Optimized Cross-product Traversal)** framework. This framework typically utilizes two main encrypted data structures to perform conjunctive queries:

- **Core Schemes:**

  - **TSet (managed by a TEDB-like component/handler):** This structure primarily stores mappings from keywords to encrypted document identifiers. In a conjunctive query, TSet is used to retrieve a set of encrypted document identifiers that are associated with the least frequent keyword in the query. To ensure strong privacy guarantees and support efficient non-interactive deletion, the SDSSE implementation manages TSet using an instance of the **Aura** single-keyword SSE scheme. Aura itself is designed to provide forward and Type-II backward privacy.

  - **XSet (managed by an XEDB-like component/handler):** This structure stores encrypted "cross-tags" (referred to as `xtag` in the research). These `xtags` are cryptographically derived from keyword-document ID pairs, incorporating a counter specific to each keyword (maintained by the client). After the client retrieves an initial list of encrypted document entries from TSet, it generates "verification tokens" (`xtoken`) for the remaining keywords in the conjunctive query. These `xtokens` are then sent to the server to be checked against the `xtags` stored in XSet. This step verifies if the documents identified from TSet indeed contain all the other keywords specified in the conjunction. Similar to TSet, the XSet in this project is also managed by an instance of the Aura scheme, ensuring that both components of the conjunctive query mechanism benefit from robust privacy features and non-interactive deletion capabilities.

  The `SDSSECQSClient` (and its command-line wrapper `SDSSECQSCLI`) orchestrates the operations on both TSet and XSet. When a document is added or deleted:

  1. **Updates:** When adding a document $ind$ with keyword $w$, the client performs the following cryptographic operations:

     a. **Token Generation:**
        - Use PRF $F$ with secret key $k$ to derive $k_w = F(k, w)$
        - Symmetrically encrypt the identifier: $e = \text{SE.Enc}(k_w, ind)$

     b. **Component Generation:**
        - Generate component $y$ using PRFs $Fp$ with:
          - Key $k_i$: $y = Fp(ki, ind)$
          - Key $k_z$ and counter $c$: $z = Fp(kz, w||c)$
          - Counter $c$ from $\text{CT}$ map for keyword $w$

     c. **Storage Operations:**
        - Add entry $(e||y||c)$ to TSet's Aura instance
        - Compute and add $\text{xtag}$ to XSet's Aura instance:
          - $\text{xtag} = g^{\text{Fp}(k_x,w) \cdot \text{xind}}$
          - Where $\text{xind}$ relates to $y \cdot z$
          - $g$ is the group generator

     d. **Deletion Handling:**
        - Leverage Aura scheme's capabilities for non-interactive deletions

  2. **Search:** For a conjunctive search query $(w_1, \dots, w_n)$, assuming $w_1$ is the least frequent keyword:

     a. **Initial Query:**
        - Client queries TSet (via Aura instance) using $w_1$
        - Retrieves candidate encrypted entries $(e||y||c)$

     b. **Token Generation:**
        - For each candidate entry with counter $c$ (denoted as $i$):
          - For each remaining keyword $w_j$ (where $j > 1$):
            - Generate $\text{xtoken}_{[i,j]} = g^{\text{Fp}(k_z,w_1||i) \cdot \text{Fp}(k_x,w_j)}$

     c. **Verification:**
        - Server uses:
          - Generated $\text{xtokens}$
          - $y$ component from TSet entries
        - Checks for matches against $\text{xtags}$ in XSet

  This design ensures that both the initial single-keyword lookup on TSet and the subsequent conjunctive verification against XSet are protected by forward and backward privacy, offering a more comprehensive security model than prior OXT-based approaches like ODXT, which might not fully protect the XSet or offer non-interactive deletion.

  The codebase might also feature an enhanced scheme, **SDSSE-CQ-S**, which aims for a stronger level of backward privacy (Type-O-). This is achieved by incorporating additional randomness into the `xtag` and `xtoken` generation, making these tokens specific to the context of the current least-frequent keyword in the query, potentially with some trade-off in performance.

- **Cryptographic Primitives:**
  The fundamental cryptographic building blocks remain as described:

  - **Pairing-Based Cryptography (PBC):** The `libpbc` library is used for elliptic curve pairings, essential for the trapdoor mechanisms and other cryptographic constructions (e.g., operations involving the group generator `g` mentioned for `xtags` and `xtokens`). Parameters are loaded from `pairing.param` and `elliptic_g`.
  - **Symmetric Encryption (SE):** The SM4 block cipher is used for encrypting identifiers (e.g., `SE.Enc(kw, ind)`).
  - **Pseudorandom Functions (PRF):** PRFs (denoted `F` and `Fp` in the research) are crucial. `Fp` is often a PRF whose output is in a prime-order group. These are likely implemented using standard cryptographic hash functions like SM3, as mentioned for key derivation, tag generation, and token construction.
  - **GGM Trees (Goldreich-Goldwasser-Micali):** These are fundamental for constructing puncturable PRFs, a key technique used within the Aura scheme to achieve forward privacy.
  - **Bloom Filters:** Employed by the Aura scheme to efficiently represent sets (like deleted items) and check for membership with a controlled false-positive rate, aiding in non-interactive deletion.

- **Client-Server Architecture:**

  - The `SSEServerStandalone` acts as the storage and computation backend. It receives encrypted data structures (TSet and XSet managed by Aura) and search tokens from the client. It performs checks against these structures based on client requests.
  - Clients, like `SDSSECQSClient`, perform the primary cryptographic operations to generate ciphertexts for storage, update tokens (for additions/deletions in Aura), and search tokens (for TSet queries and `xtokens` for XSet verification).
  - Communication is performed over TCP/IP sockets, with messages serialized using **MessagePack**.

- **State Management (Client-Side):**
  - The `SDSSECQSClient` maintains a crucial client-side state, notably the `CT` map. This map stores counters for each keyword (e.g., `CT[keyword]` holds `c`, the number of times a keyword has been involved in an update or its current version).
  - These counters are essential for generating the correct cryptographic values (like `z`, `xtags`, and `xtokens`) for updates and searches, as detailed in the scheme's algorithms.
  - The `SDSSECQSCLI` rebuilds this `CT` map on each invocation by parsing the input file. For persistent applications, this state would ideally be stored more durably.

## Evaluation & Benchmarks

The project includes several programs for performance evaluation and testing individual components.

### Micro-benchmarks

Located in the `Test/` directory, these executables test specific cryptographic building blocks:

- `SM4Test`: Validates SM4 block cipher and GCM mode.
- `BloomFilterTest`: Tests Bloom filter implementation, including hash functions and false-positive rates.
- `GGMTest`: Exercises GGM tree generation and node derivation.
- `SSETest`: Performs end-to-end tests of the basic SSE client handler (TEDB functionality).

Run them after building, e.g.:

```bash
./build/bin/SSETest
```

### SDSSECQ / SDSSECQS Evaluation Programs

These programs (`SDSSECQ.cpp` for single keyword, `SDSSECQS.cpp` for conjunctive) measure insertion, deletion, and search performance.

```bash
# Syntax:  executable  <#w1_docs>  <#w2_docs>  <#deletions>
# (w1 and w2 represent different keywords, e.g., "alice" and "bob")
./build/bin/SDSSECQ   10000  8000  1000
./build/bin/SDSSECQS  10000  8000  1000
```

They output average times in microseconds (µs) for updates and milliseconds (ms) for searches.

An automated script for running a series of these evaluations is available:

```bash
cd ./Data
bash ./Evaluation
```

## Project Layout

- `BF/` - Bloom-filter implementation & hashing
- `Core/` - Client logic (SDSSECQClient, SDSSECQSClient, SSEClientHandler, SSEServerHandler)
- `Data/` - Example datasets (1984.txt), EC parameters (pairing.param, elliptic_g), evaluation script
- `GGM/` - GGM tree data structure
- `Server/` - Standalone MessagePack-based TCP server (SSEServerStandalone.cpp)
- `SDK/` - (Potentially for public headers, WIP)
- `Test/` - Micro-benchmarks & unit tests
- `Util/` - Common helpers, crypto wrappers (SM4), PBC adapter
- `extern/` - Vendored dependencies (e.g., vcpkg submodule, args.hxx)

## License

This project is licensed under the terms of the GNU General Public License v3.0. See the [`LICENSE` file](./LICENSE) for details.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
