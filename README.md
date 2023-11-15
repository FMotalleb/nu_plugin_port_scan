# nu_plugin_port_scan

A [nushell](https://www.nushell.sh/) plugin for scanning ports on a target

Similar to `nc -vz {ip} {port} -w {timeout}` the parameters are mapped to `port scan {ip} {port} -t {timeout}`

## Examples

```bash
~> port scan 8.8.8.8 53
╭─────────┬───────────────────╮
│ address │ 8.8.8.8           │
│ port    │ 53                │
│ result  │ Open              │
│ is_open │ true              │
│ elapsed │ 140ms 965µs 400ns │
╰─────────┴───────────────────╯
```

```bash
~> 50..60 | par-each { |it| port scan 8.8.8.8 $it -t 100ms } |  where is_open | collect { $in }
╭───┬─────────┬──────┬────────┬─────────┬──────────────────╮
│ # │ address │ port │ result │ is_open │     elapsed      │
├───┼─────────┼──────┼────────┼─────────┼──────────────────┤
│ 0 │ 8.8.8.8 │   53 │ Open   │ true    │ 39ms 704µs 200ns │
╰───┴─────────┴──────┴────────┴─────────┴──────────────────╯
```

```bash
~> [8.8.8.8, 1.1.1.1, 1.0.0.1, 4.2.2.4] | par-each { |it| port scan $it 53 -t 1sec } |  where is_open | collect { $in } | sort-by elapsed
╭───┬─────────┬──────┬────────┬─────────┬──────────────────╮
│ # │ address │ port │ result │ is_open │     elapsed      │
├───┼─────────┼──────┼────────┼─────────┼──────────────────┤
│ 0 │ 8.8.8.8 │   53 │ Open   │ true    │ 40ms 519µs 900ns │
│ 1 │ 1.0.0.1 │   53 │ Open   │ true    │ 93ms 471µs 500ns │
│ 2 │ 4.2.2.4 │   53 │ Open   │ true    │       97ms 130µs │
│ 3 │ 1.1.1.1 │   53 │ Open   │ true    │ 99ms 867µs 500ns │
╰───┴─────────┴──────┴────────┴─────────┴──────────────────╯
```

## Installing

* using [nupm](https://github.com/nushell/nupm)

```bash
git clone https://github.com/FMotalleb/nu_plugin_port_scan.git
nupm install --path nu_plugin_port_scan -f
```

* or compile manually

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
