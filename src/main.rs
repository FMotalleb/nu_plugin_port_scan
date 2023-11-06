use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use nu_plugin::{self, EvaluatedCall, LabeledError};
use nu_protocol::{Category, PluginSignature, Record, Span, SyntaxShape, Value};

pub struct Plugin;

impl nu_plugin::Plugin for Plugin {
    fn signature(&self) -> Vec<PluginSignature> {
        vec![PluginSignature::build("port scan")
            .required(
                "target",
                SyntaxShape::String,
                "target address to check for open port",
            )
            .required("port", SyntaxShape::Int, "port to be checked")
            .named(
                "timeout",
                SyntaxShape::Duration,
                "time before giving up the connection. (default: 60 Seconds)",
                Option::Some('t'),
            )
            .usage("scan port on a target")
            .category(Category::Experimental)]
    }

    fn run(
        &mut self,
        _name: &str,
        call: &EvaluatedCall,
        _input: &Value,
    ) -> Result<Value, LabeledError> {
        let default_timeout = 60000000000;
        let cols = vec![
            "address".to_owned(),
            "port".to_owned(),
            "result".to_owned(),
            "elapsed (ms)".to_string(),
        ];
        let target: Value = call.req(0).unwrap();
        let port: Value = call.req(1).unwrap();

        let timeout: i64 = call
            .get_flag_value("timeout")
            .unwrap_or(Value::duration(default_timeout, call.head))
            .as_duration()
            .unwrap();
        let duration = Duration::from_nanos(timeout.unsigned_abs());

        let address = format!("{}:{}", target.as_string().unwrap(), port.as_int().unwrap())
            .parse::<SocketAddr>();

        if address.is_err() {
            let span = Span::new(target.span().start, port.span().end);
            return Err(LabeledError {
                label: "Address parser exception".to_string(),
                msg: format!(
                    "as `{}:{}` got `{}` error",
                    target.as_string().unwrap(),
                    port.as_int().unwrap(),
                    address.err().unwrap().to_string()
                ),
                span: Option::Some(span),
            });
        }
        let now = Instant::now();
        if let Ok(_) = TcpStream::connect_timeout(&address.unwrap(), duration) {
            let elapsed = now.elapsed().as_millis();
            return Ok(Value::Record {
                val: Record {
                    cols: cols,
                    vals: vec![
                        Value::string(target.as_string().unwrap(), target.span()),
                        Value::string(port.as_int().unwrap().to_string(), port.span()),
                        Value::string("Open".to_string(), call.head),
                        Value::string(elapsed.to_string(), call.head),
                    ],
                },
                internal_span: call.head,
            });
        } else {
            let elapsed = now.elapsed().as_millis();
            return Ok(Value::Record {
                val: Record {
                    cols: cols,
                    vals: vec![
                        Value::string(target.as_string().unwrap(), target.span()),
                        Value::string(port.as_string().unwrap(), port.span()),
                        Value::string("Closed".to_string(), call.head),
                        Value::string(elapsed.to_string(), call.head),
                    ],
                },
                internal_span: call.head,
            });
        }
    }
}

fn main() {
    nu_plugin::serve_plugin(&mut Plugin {}, nu_plugin::MsgPackSerializer {})
}
