use core::panic;
use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use nu_plugin::{self, EvaluatedCall, LabeledError};
use nu_protocol::{record, Category, PluginExample, PluginSignature, Span, SyntaxShape, Value};

pub struct Plugin;

const DEFAULT_TIMEOUT: i64 = 60000000000;
impl nu_plugin::Plugin for Plugin {
    fn signature(&self) -> Vec<PluginSignature> {
        vec![PluginSignature::build("port scan")
            .usage("The `port scan` command serves a similar purpose to the `nc -vz {ip} {port}` command,\nIt allows you to detect open ports on a target and provides valuable information about the connection time.")
            .required(
                "target ip",
                SyntaxShape::String,
                "target IP address to check for open port",
            )
            .required("port", SyntaxShape::Int, "port to be checked")
            .named(
                "timeout",
                SyntaxShape::Duration,
                "time before giving up the connection. (default: 60 Seconds)",
                Some('t'),
            )
            .plugin_examples(
                vec![
                    PluginExample{
                        example: "port scan 8.8.8.8 53 -t 1sec".to_string(),
                        description : "this will create a Tcp connection to port 53 on 8.8.8.8 (Google's public dns) and return the connection time".to_string(),
                        result: Some(
                            Value::record(
                                record! {
                                    "address" => Value::test_string("8.8.8.8".to_string()),
                                    "port" => Value::test_int(53),
                                    "result" => Value::test_string("Open", ),
                                    "elapsed" =>  Value::test_int(40),
                                },
                                Span::unknown(),
                            )
                        ),
                    },
                    PluginExample{
                        example: "port scan 8.8.8.8 54 -t 1sec".to_string(),
                        description : "this will create a Tcp connection to port 54 on 8.8.8.8 (Google's public dns). this will result in an error".to_string(),
                        result: Some(
                                Value::record(
                                    record! {
                                        "address" => Value::test_string("8.8.8.8".to_string()),
                                        "port" => Value::test_int(54),
                                        "result" => Value::test_string("Closed", ),
                                        "elapsed" =>  Value::test_int(1000),
                                    },
                                    Span::unknown(),
                                )
                            ),
                    },
                    PluginExample{
                        example: "7880..8000 | each { |it| port scan 127.0.0.1 $it -t 1ms } | where result == Open".to_string(),
                        description : "This command will scan any port from 7880 to 8000 on localhost and return open ports in range".to_string(),
                        result: None,
                    },
                ],)
            .category(Category::Network)]
    }

    fn run(
        &mut self,
        _name: &str,
        call: &EvaluatedCall,
        _input: &Value,
    ) -> Result<Value, LabeledError> {
        let (target, port) = extract_params(call);

        let (real_target, real_port) = load_address(&target, &port);

        let timeout: i64 = match call.get_flag_value("timeout") {
            Some(duration) => match duration.as_duration() {
                Ok(value) => value,
                Err(_) => panic!("Error reading duration"),
            },
            None => DEFAULT_TIMEOUT,
        };
        let duration = Duration::from_nanos(timeout.unsigned_abs());

        let address = format!("{}:{}", real_target, port.as_int().unwrap()).parse::<SocketAddr>();

        if address.is_err() {
            let span = Span::new(target.span().start, port.span().end);
            return Err(LabeledError {
                label: "Address parser exception".to_string(),
                msg: format!(
                    "as `{}:{}` got `{}` error. do not use domain name in address",
                    real_target,
                    real_port,
                    address.err().unwrap().to_string()
                ),
                span: Some(span),
            });
        }
        let now = Instant::now();
        let is_open = check_connection(address, duration);
        let elapsed = now.elapsed().as_millis();
        let result = match is_open {
            true => "Open",
            false => "Closed",
        };

        Ok(Value::record(
            record! {
                "address" => Value::string(real_target, target.span()),
                "port" => Value::int(real_port, port.span()),
                "result" => Value::string(result.to_string(), call.head),
                "is_open"=> Value::bool(is_open, call.head),
                "elapsed" =>  Value::int(elapsed.try_into().unwrap(), call.head),
            },
            call.head,
        ))
    }
}

fn check_connection(
    address: Result<SocketAddr, std::net::AddrParseError>,
    duration: Duration,
) -> bool {
    match TcpStream::connect_timeout(&address.unwrap(), duration) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn load_address(target: &Value, port: &Value) -> (String, i64) {
    let real_target = match target.as_string() {
        Ok(value) => value,
        Err(_) => panic!("Address value cannot be parsed to string"),
    };

    let real_port = match port.as_int() {
        Ok(value) => value,
        Err(_) => panic!("Port value cannot be parsed to integer"),
    };
    (real_target, real_port)
}

fn extract_params(call: &EvaluatedCall) -> (Value, Value) {
    let target: Value = match call.req(0) {
        Ok(value) => value,
        Err(_) => panic!("Given value for target is not correct"),
    };
    let port: Value = match call.req(1) {
        Ok(value) => value,
        Err(_) => panic!("Given value for port is not correct"),
    };
    (target, port)
}

fn main() {
    nu_plugin::serve_plugin(&mut Plugin {}, nu_plugin::MsgPackSerializer {})
}
