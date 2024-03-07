use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use nu_plugin::{self, EvaluatedCall, LabeledError};
use nu_protocol::{
    record, Category, PluginExample, PluginSignature, ShellError, Span, SyntaxShape, Value,
};

pub struct Plugin;

const DEFAULT_TIMEOUT: i64 = 60000000000;
impl nu_plugin::Plugin for Plugin {
    fn signature(&self) -> Vec<PluginSignature> {
        vec![PluginSignature::build("port scan")
            .usage("The `port scan` command serves a similar purpose to the `nc -vz {ip} {port}` command,\nIt allows you to detect open ports on a target and provides valuable information about the connection time.")
            .required(
                "target IP",
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
                                    "is_open"=> Value::test_bool(true, ),
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
                                        "is_open"=> Value::test_bool(false, ),
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
        _config: &Option<Value>,
        call: &EvaluatedCall,
        _input: &Value,
    ) -> Result<Value, LabeledError> {
        let (target, port) = match extract_params(call) {
            Ok((target, port)) => (target, port),
            Err(e) => return Err(LabeledError::from(e)),
        };

        let real_target = match target.as_str() {
            Ok(real_target) => real_target,
            Err(e) => {
                return Err(LabeledError {
                    label: "Target Address error".to_string(),
                    msg: e.to_string(),
                    span: Some(target.span()),
                })
            }
        };
        let real_port = match port.as_int() {
            Ok(real_port) => real_port,
            Err(e) => {
                return Err(LabeledError {
                    label: "Target Address error".to_string(),
                    msg: e.to_string(),
                    span: Some(port.span()),
                })
            }
        };
        let address = match format!("{}:{}", real_target, real_port).parse::<SocketAddr>() {
            Ok(address) => address,
            Err(err) => {
                let span = Span::new(target.span().start, port.span().end);
                return Err(LabeledError {
                    label: "Address parser exception".to_string(),
                    msg: format!(
                        "as `{}:{}` got `{}`. note: do not use domain name in address.",
                        real_target, real_port, err,
                    ),
                    span: Some(span),
                });
            }
        };
        let (is_open, elapsed) = match scan(call, address) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        let str_result = match is_open {
            true => "Open",
            false => "Closed",
        };
        let elapsed: i64 = match elapsed.try_into() {
            Ok(elapsed) => elapsed,
            Err(_) => 0,
        };
        Ok(Value::record(
            record! {
                "address" => Value::string(real_target, target.span()),
                "port" => Value::int(real_port, port.span()),
                "result" => Value::string(str_result, call.head),
                "is_open"=> Value::bool(is_open, call.head),
                "elapsed" =>  Value::duration(elapsed, call.head),
            },
            call.head,
        ))
    }
}

fn scan(call: &EvaluatedCall, target_address: SocketAddr) -> Result<(bool, u128), LabeledError> {
    let timeout: i64 = match call.get_flag_value("timeout") {
        Some(duration) => match duration.as_duration() {
            Ok(timeout) => timeout,
            Err(_) => DEFAULT_TIMEOUT,
        },
        None => DEFAULT_TIMEOUT,
    };
    let duration = Duration::from_nanos(timeout.unsigned_abs());

    let now = Instant::now();
    let is_open = check_connection(target_address, duration);
    let elapsed = now.elapsed().as_nanos();

    Ok((is_open, elapsed))
}

fn check_connection(address: SocketAddr, duration: Duration) -> bool {
    match TcpStream::connect_timeout(&address, duration) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn extract_params(call: &EvaluatedCall) -> Result<(Value, Value), ShellError> {
    let target: Value = match call.req(0) {
        Ok(value) => value,
        Err(_) => {
            return Err(ShellError::MissingParameter {
                param_name: "target IP".to_string(),
                span: call.head,
            })
        }
    };
    let port: Value = match call.req(1) {
        Ok(value) => value,
        Err(_) => {
            return Err(ShellError::MissingParameter {
                param_name: "target Port".to_string(),
                span: call.head,
            })
        }
    };
    Ok((target, port))
}

fn main() {
    nu_plugin::serve_plugin(&mut Plugin {}, nu_plugin::MsgPackSerializer {})
}
