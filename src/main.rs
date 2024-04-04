mod port_scan;


use nu_plugin::{PluginCommand};

use crate::port_scan::PortScan;

pub struct PortScanPlugin;

impl nu_plugin::Plugin for PortScanPlugin {
    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin=Self>>> {
        vec![Box::new(PortScan::new())]
    }
}


fn main() {
    nu_plugin::serve_plugin(&mut PortScanPlugin {}, nu_plugin::MsgPackSerializer {})
}
