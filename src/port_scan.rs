use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{Category, ErrorLabel, LabeledError, PipelineData, record, ShellError, Signature, Span, SyntaxShape, Value};
use crate::PortScanPlugin;


const DEFAULT_TIMEOUT: i64 = 60000000000;

#[derive(Default)]
pub struct PortScan {}

impl PortScan {
    pub(crate) fn new() -> PortScan {
        PortScan {}
    }
}

impl PortScan {
    fn scan(call: &EvaluatedCall, target_address: SocketAddr) -> Result<(bool, u128), LabeledError> {
        let timeout: i64 = match call.get_flag_value("timeout") {
            Some(duration) => duration.as_duration().unwrap_or_else(|_| DEFAULT_TIMEOUT),
            None => DEFAULT_TIMEOUT,
        };
        let duration = Duration::from_nanos(timeout.unsigned_abs());

        let now = Instant::now();
        let is_open = Self::check_connection(target_address, duration);
        let elapsed = now.elapsed().as_nanos();

        Ok((is_open, elapsed))
    }
    fn check_connection(address: SocketAddr, duration: Duration) -> bool {
        match TcpStream::connect_timeout(&address, duration) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn extract_params(call: &EvaluatedCall) -> Result<(nu_protocol::Value, nu_protocol::Value), ShellError> {
        let target: nu_protocol::Value = match call.req(0) {
            Ok(value) => value,
            Err(_) => {
                return Err(ShellError::MissingParameter {
                    param_name: "target IP".to_string(),
                    span: call.head,
                });
            }
        };
        let port: nu_protocol::Value = match call.req(1) {
            Ok(value) => value,
            Err(_) => {
                return Err(ShellError::MissingParameter {
                    param_name: "target Port".to_string(),
                    span: call.head,
                });
            }
        };
        Ok((target, port))
    }
}

impl PluginCommand for PortScan {
    type Plugin = PortScanPlugin;

    fn name(&self) -> &str {
        "port scan"
    }

    fn signature(&self) -> Signature {
        Signature::build("port scan")
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
            // .plugin_examples(
            //     vec![
            //         PluginExample{
            //             example: "port scan 8.8.8.8 53 -t 1sec".to_string(),
            //             description : "this will create a Tcp connection to port 53 on 8.8.8.8 (Google's public dns) and return the connection time".to_string(),
            //             result: Some(
            //                 Value::record(
            //                     record! {
            //                         "address" => Value::test_string("8.8.8.8".to_string()),
            //                         "port" => Value::test_int(53),
            //                         "result" => Value::test_string("Open", ),
            //                         "is_open"=> Value::test_bool(true, ),
            //                         "elapsed" =>  Value::test_int(40),
            //                     },
            //                     Span::unknown(),
            //                 )
            //             ),
            //         },
            //         PluginExample{
            //             example: "port scan 8.8.8.8 54 -t 1sec".to_string(),
            //             description : "this will create a Tcp connection to port 54 on 8.8.8.8 (Google's public dns). this will result in an error".to_string(),
            //             result: Some(
            //                 Value::record(
            //                     record! {
            //                             "address" => Value::test_string("8.8.8.8".to_string()),
            //                             "port" => Value::test_int(54),
            //                             "result" => Value::test_string("Closed", ),
            //                             "is_open"=> Value::test_bool(false, ),
            //                             "elapsed" =>  Value::test_int(1000),
            //                         },
            //                     Span::unknown(),
            //                 )
            //             ),
            //         },
            //         PluginExample{
            //             example: "7880..8000 | each { |it| port scan 127.0.0.1 $it -t 1ms } | where result == Open".to_string(),
            //             description : "This command will scan any port from 7880 to 8000 on localhost and return open ports in range".to_string(),
            //             result: None,
            //         },
            //     ],)
            .category(Category::Network)
    }

    fn usage(&self) -> &str {
        "The `port scan` command serves a similar purpose to the `nc -vz {ip} {port}` command,\nIt allows you to detect open ports on a target and provides valuable information about the connection time."
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let (target, port) = match Self::extract_params(call) {
            Ok((target, port)) => (target, port),
            Err(e) => return Err(LabeledError::from(e)),
        };

        let real_target = match target.as_str() {
            Ok(real_target) => real_target,
            Err(e) => {
                return Err(LabeledError {
                    msg: e.to_string(),
                    labels: vec![ErrorLabel { text: "Target Address error".to_string(), span: target.span() }],
                    code: None,
                    url: None,
                    help: None,
                    inner: vec![],
                });
            }
        };
        let real_port = match port.as_int() {
            Ok(real_port) => real_port,
            Err(e) => {
                return Err(LabeledError {
                    msg: e.to_string(),
                    labels: vec![ErrorLabel { text: "Target Address error".to_string(), span: port.span() }],
                    code: None,
                    url: None,
                    help: None,
                    inner: vec![],
                });
            }
        };
        let address = match format!("{}:{}", real_target, real_port).parse::<SocketAddr>() {
            Ok(address) => address,
            Err(err) => {
                let span = Span::new(target.span().start, port.span().end);
                return Err(LabeledError {
                    msg: format!(
                        "as `{}:{}` got `{}`. note: do not use domain name in address.",
                        real_target, real_port, err,
                    ),
                    labels: vec![ErrorLabel { text: "Address parser exception".to_string(), span }],
                    code: None,
                    url: None,
                    help: None,
                    inner: vec![],
                });
            }
        };
        let (is_open, elapsed) = match Self::scan(call, address) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        let str_result = match is_open {
            true => "Open",
            false => "Closed",
        };
        let elapsed: i64 = elapsed.try_into().unwrap_or_else(|_| 0);

        Ok(PipelineData::Value(
            Value::record(
                record! {
                "address" => nu_protocol::Value::string(real_target, target.span()),
                "port" => nu_protocol::Value::int(real_port, port.span()),
                "result" => nu_protocol::Value::string(str_result, call.head),
                "is_open"=> nu_protocol::Value::bool(is_open, call.head),
                "elapsed" =>  nu_protocol::Value::duration(elapsed, call.head),
            },
                call.head,
            ),
            None,
        )
        )
    }
}

