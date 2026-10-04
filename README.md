# mepa_spidev_proxy

Standalone SPI proxy daemon (`lan80xx-spid`) and its debug CLI
(`spiproxy-cli`) for the Microchip LAN80xx 25G PHY.

## Why a proxy

`/dev/spidevX.Y` is a single, exclusive resource, but several unrelated
processes may all need register access to the same LAN80xx at the same time:
the `sw-mepa` or `mesa/mepa` configuration path, a PTP agent, debug tooling, etc.
Letting each open `/dev/spidev` directly interleaves their transfers and corrupts
multi-step sequences (paged register access, read-modify-write, and especially the
MCU mailbox protocol).

`lan80xx-spid` is the single process that opens and owns `/dev/spidev`
(exclusive `flock`). Every other application connects to it over an
`AF_UNIX SOCK_SEQPACKET` socket instead of opening the device, and the daemon
serializes all access so concurrent clients cannot corrupt each other.

The clients get:

- single register `READ` / `WRITE`, and atomic `BATCH` sequences;
- `CLAIM` / `RELEASE` whole-device leases (with client-supplied cleanup ops run
  on disconnect);
- full MCU `MAILBOX` request/response runs;
- a hardware `RESET` primitive (pulses a reset GPIO via the kernel GPIO v2
  chardev uAPI);
- an egress timestamp FIFO service (`TSFIFO_SUB` / `TSFIFO_UNSUB`): the
  daemon drains the transmit timestamp FIFO of a subscribed slice and pushes
  its entries to the subscriber (a PTP stack), while no other client may read
  the FIFO rows;
- `STATS` / `TRACE` diagnostics, plus a cross-client "lint" layer that warns on
  page-ride, clear-on-read counter poaching, and RMW races.

`spiproxy-cli` is a thin command-line client for poking the daemon by hand.

### Components

| Binary          | Source            | Role                                             |
|-----------------|-------------------|--------------------------------------------------|
| `lan80xx-spid`  | `lan80xx_spid.c`  | The daemon: owns `/dev/spidev`, serializes access|
|                 | `ts_fifo.c`       | Its egress timestamp FIFO service                |
| `spiproxy-cli`  | `spiproxy_cli.c`  | Debug CLI client                                 |
| (shared header) | `spiproxy.h`      | Wire protocol contract (12-byte header + ops)    |

## Building and installing

The daemon and CLI does not have any beyond libc (it means it does not need `mepa`):

```sh
cmake -B build -S .
cmake --build build
cmake --install build --prefix <prefix>
```

Installing:

```
<prefix>/bin/lan80xx-spid
<prefix>/bin/spiproxy-cli
<prefix>/include/spi_proxy/spiproxy.h            # the protocol API/contract
<prefix>/lib/cmake/mepa_spidev_proxy/mepa_spidev_proxyConfig.cmake     # find_package()
<prefix>/lib/cmake/mepa_spidev_proxy/mepa_spidev_proxyTargets.cmake
<prefix>/lib/cmake/mepa_spidev_proxy/mepa_spidev_proxyConfigVersion.cmake
```

### Options

| Option            | Default | Meaning                                                        |
|-------------------|---------|----------------------------------------------------------------|
| `SPIPROXY_STATIC` | `OFF`   | Fully static executables (for initramfs targets).              |
| `SPIPROXY_TESTS`  | `OFF`   | Unit tests, run with `ctest` (no hardware needed).             |

```sh
cmake -B build -S . -DSPIPROXY_STATIC=ON
```

## How sw-mepa consumes this package

`sw-mepa` is a client of the proxy: `mepa_demo/phy_only.c` speaks the
`spiproxy.h` protocol in its `-P proxy:<sock>` mode. Its build does

```cmake
find_package(mepa_spidev_proxy CONFIG QUIET)
```

- If this package is installed and found, `sw-mepa` links
  `mepa_spidev_proxy::spiproxy` (which supplies `<spi_proxy/spiproxy.h>`), defines
  `MEPA_HAS_SPIPROXY`, and the `-P proxy:<sock>` client mode is compiled in.
- If it is not found, `sw-mepa` builds normally without proxy mode
  (direct-spidev PHY-only access still works).

So install `mepa_spidev_proxy` first, then point `sw-mepa`'s configure at the same
prefix:

```sh
cmake --install <mepa_spidev_proxy-build> --prefix /opt/mepa
# ... then, when configuring sw-mepa:
#   -DCMAKE_PREFIX_PATH=/opt/mepa   (so its find_package(mepa_spidev_proxy) hits)
```

Any other application (a PTP agent, custom tooling) consumes the same package
the same way, or just links `spiproxy.h`'s protocol directly.

## Running

```sh
# Daemon: own /dev/spidev1.0 at 10 MHz, listen on the default socket
# (/run/lan80xx-spid.sock). Add -r <gpio-line-name> to enable the RESET op.
lan80xx-spid -d /dev/spidev1.0 -f 10000000 -r lan8023-rst
```

Daemon flags (`-h` for the full list): `-d` spidev node (required), `-s`
socket path, `-p` SPI read padding bytes, `-f` SPI clock in Hz (default 5 MHz),
`-r` reset GPIO line name, `-L` event log file.

```sh
# CLI: point it at the socket with -s if not the default
spiproxy-cli read  <slice> <mmd> <reg>
spiproxy-cli write <slice> <mmd> <reg> <val>
spiproxy-cli bench <n>            # proxied read round-trip stats
spiproxy-cli hammer <seconds>     # low-priority read flood
spiproxy-cli claimtest <ms>       # claim, read, hold, release
spiproxy-cli tsfifo <slice> [period_us [count]]  # print the TS FIFO pushes
```

### Egress timestamp FIFO

A PTP stack timestamping with the PHY in standalone mode gets the transmit
timestamps (Sync in two-step, Delay_Req) from the egress TS FIFO of each slice.
Reading `TSFIFO_9` pops a row, so the FIFO can have one reader only.

- `TSFIFO_SUB {slice, period_us}` makes the daemon poll that FIFO every
  `period_us` (default 5 ms, 1 ms .. 1 s)
- Each poll that finds rows sends one push (`seq` = 0) with up to 16 entries
  and the `EGR_TSFIFO_DROP_CNT` value, see `spiproxy.h`.
- After a hardware `RESET`, subscribers get a reset notice: the TSU
  configuration is gone and must be programmed again.
- The drain runs between any two queued operations, during a mailbox wait and
  while another client holds a `CLAIM`: PTP comes first.
- Use a dedicated connection for the subscription.

```sh
cmake -B build -S . -DMESA_ROOT_DIR=<mesa> -DSPIPROXY_TESTS=ON
cmake --build build && (cd build && ctest)
```

See the header comment in `spiproxy_cli.c` for the complete subcommand list.
