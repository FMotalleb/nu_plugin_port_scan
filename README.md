# nu_plugin_port_scan

A [nushell](https://www.nushell.sh/) plugin for scanning ports on a target

Similar to `nc -vz {ip} {port} -w {timeout}` the parameters are mapped to `port scan {ip} {port} -t {timeout}`

## Examples

```bash
~> port scan 8.8.8.8 53
╭─────────┬─────────╮
│ address │ 8.8.8.8 │
│ port    │ 53      │
│ result  │ Open    │
│ is_open │ true    │
│ elapsed │ 39      │
╰─────────┴─────────╯
```

```bash
~> 50..60 | par-each { |it| port scan 8.8.8.8 $it -t 100ms } |  where is_open | collect { $in }
╭───┬─────────┬──────┬────────┬─────────┬─────────╮
│ # │ address │ port │ result │ is_open │ elapsed │
├───┼─────────┼──────┼────────┼─────────┼─────────┤
│ 0 │ 8.8.8.8 │   53 │ Open   │ true    │      41 │
╰───┴─────────┴──────┴────────┴─────────┴─────────╯
```

## Installing

* via git

```bash
git clone https://github.com/FMotalleb/nu_plugin_port_scan.git
cd nu_plugin_port_scan
cargo build
register target/debug/nu_plugin_port_scan
```

* or using cargo

```bash
cargo install nu_plugin_port_scan
register  ~/.cargo/bin/nu_plugin_port_scan
```
