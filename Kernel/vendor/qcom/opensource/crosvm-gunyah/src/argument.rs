#![allow(dead_code)]
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

//! Handles argument parsing.
//!
//! # Example
//!
//! ```
//! # use crosvm::argument::{Argument, Error, print_help, set_arguments};
//! # let args: std::slice::Iter<String> = [].iter();
//! let arguments = &[
//!     Argument::positional("FILES", "files to operate on"),
//!     Argument::short_value('p', "program", "PROGRAM", "Program to apply to each file"),
//!     Argument::short_value('c', "cpus", "N", "Number of CPUs to use. (default: 1)"),
//!     Argument::flag("unmount", "Unmount the root"),
//!     Argument::short_flag('h', "help", "Print help message."),
//! ];
//!
//! let match_res = set_arguments(args, arguments, |name, value| {
//!     match name {
//!         "" => println!("positional arg! {}", value.unwrap()),
//!         "program" => println!("gonna use program {}", value.unwrap()),
//!         "cpus" => {
//!             let v: u32 = value.unwrap().parse().map_err(|_| {
//!                 Error::InvalidValue {
//!                     value: value.unwrap().to_owned(),
//!                     expected: String::from("this value for `cpus` needs to be integer"),
//!                 }
//!             })?;
//!         }
//!         "unmount" => println!("gonna unmount"),
//!         "help" => return Err(Error::PrintHelp),
//!         _ => unreachable!(),
//!     }
//!     unreachable!();
//! });
//!
//! match match_res {
//!     Ok(_) => println!("running with settings"),
//!     Err(Error::PrintHelp) => print_help("best_program", "FILES", arguments),
//!     Err(e) => println!("{}", e),
//! }
//! ```

use std::convert::TryFrom;
use std::result;
use std::str::FromStr;

use thiserror::Error;

/// An error with argument parsing.
#[derive(Error, Debug)]
pub enum Error {
    /// Free error for use with the `serde_keyvalue` crate parser.
    #[error("failed to parse key-value arguments: {0}")]
    ConfigParserError(String),
    /// The argument was required.
    #[error("expected argument: {0}")]
    ExpectedArgument(String),
    /// The argument expects a value.
    #[error("expected parameter value: {0}")]
    ExpectedValue(String),
    /// The argument's given value is invalid.
    #[error("invalid value {value:?}: {expected}")]
    InvalidValue { value: String, expected: String },
    /// The help information was requested
    #[error("help was requested")]
    PrintHelp,
    /// There was a syntax error with the argument.
    #[error("syntax error: {0}")]
    Syntax(String),
    /// The argument was already given and none more are expected.
    #[error("too many arguments: {0}")]
    TooManyArguments(String),
    /// The argument does not expect a value.
    #[error("unexpected parameter value: {0}")]
    UnexpectedValue(String),
    /// The argument's name is unused.
    #[error("unknown argument: {0}")]
    UnknownArgument(String),
}

/// Result of a argument parsing.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum ArgumentValueMode {
    /// Specifies that an argument requires a value and that an error should be generated if
    /// no value is provided during parsing.
    Required,

    /// Specifies that an argument does not allow a value and that an error should be returned
    /// if a value is provided during parsing.
    Disallowed,

    /// Specifies that an argument may have a value during parsing but is not required to.
    Optional,
}

/// Information about an argument expected from the command line.
///
/// # Examples
///
/// To indicate a flag style argument:
///
/// ```
/// # use crosvm::argument::Argument;
/// Argument::short_flag('f', "flag", "enable awesome mode");
/// ```
///
/// To indicate a parameter style argument that expects a value:
///
/// ```
/// # use crosvm::argument::Argument;
/// // "VALUE" and "NETMASK" are placeholder values displayed in the help message for these
/// // arguments.
/// Argument::short_value('v', "val", "VALUE", "how much do you value this usage information");
/// Argument::value("netmask", "NETMASK", "hides your netface");
/// ```
///
/// To indicate an argument with no short version:
///
/// ```
/// # use crosvm::argument::Argument;
/// Argument::flag("verbose", "this option is hard to type quickly");
/// ```
///
/// To indicate a positional argument:
///
/// ```
/// # use crosvm::argument::Argument;
/// Argument::positional("VALUES", "these are positional arguments");
/// ```
pub struct Argument {
    /// The name of the value to display in the usage information.
    pub value: Option<&'static str>,
    /// Specifies how values should be handled for this this argument.
    pub value_mode: ArgumentValueMode,
    /// Optional single character shortened argument name.
    pub short: Option<char>,
    /// The long name of this argument.
    pub long: &'static str,
    /// Helpfuly usage information for this argument to display to the user.
    pub help: &'static str,
}

impl Argument {
    pub fn positional(value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            value_mode: ArgumentValueMode::Required,
            short: None,
            long: "",
            help,
        }
    }

    pub fn value(long: &'static str, value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            value_mode: ArgumentValueMode::Required,
            short: None,
            long,
            help,
        }
    }

    pub fn short_value(
        short: char,
        long: &'static str,
        value: &'static str,
        help: &'static str,
    ) -> Argument {
        Argument {
            value: Some(value),
            value_mode: ArgumentValueMode::Required,
            short: Some(short),
            long,
            help,
        }
    }

    pub fn flag(long: &'static str, help: &'static str) -> Argument {
        Argument {
            value: None,
            value_mode: ArgumentValueMode::Disallowed,
            short: None,
            long,
            help,
        }
    }

    pub fn short_flag(short: char, long: &'static str, help: &'static str) -> Argument {
        Argument {
            value: None,
            value_mode: ArgumentValueMode::Disallowed,
            short: Some(short),
            long,
            help,
        }
    }

    pub fn flag_or_value(long: &'static str, value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            value_mode: ArgumentValueMode::Optional,
            short: None,
            long,
            help,
        }
    }
}

fn parse_arguments<I, R, F>(args: I, mut f: F) -> Result<()>
where
    I: Iterator<Item = R>,
    R: AsRef<str>,
    F: FnMut(&str, Option<&str>) -> Result<()>,
{
    enum State {
        // Initial state at the start and after finishing a single argument/value.
        Top,
        // The remaining arguments are all positional.
        Positional,
        // The next string is the value for the argument `name`.
        Value { name: String },
    }
    let mut s = State::Top;
    for arg in args {
        let arg = arg.as_ref();
        loop {
            let mut arg_consumed = true;
            s = match s {
                State::Top => {
                    if arg == "--" {
                        State::Positional
                    } else if arg.starts_with("--") {
                        let param = arg.trim_start_matches('-');
                        if let Some((name, value)) = param.split_once('=') {
                            if name.is_empty() {
                                return Err(Error::Syntax(
                                    "expected parameter name before `=`".to_owned(),
                                ));
                            }
                            if value.is_empty() {
                                return Err(Error::Syntax(
                                    "expected parameter value after `=`".to_owned(),
                                ));
                            }
                            f(name, Some(value))?;
                            State::Top
                        } else {
                            State::Value {
                                name: param.to_owned(),
                            }
                        }
                    } else if arg.starts_with('-') {
                        if arg.len() == 1 {
                            return Err(Error::Syntax(
                                "expected argument short name after `-`".to_owned(),
                            ));
                        }
                        let name = &arg[1..2];
                        let value = if arg.len() > 2 { Some(&arg[2..]) } else { None };
                        if let Err(e) = f(name, value) {
                            if let Error::ExpectedValue(_) = e {
                                State::Value {
                                    name: name.to_owned(),
                                }
                            } else {
                                return Err(e);
                            }
                        } else {
                            State::Top
                        }
                    } else {
                        f("", Some(arg))?;
                        State::Positional
                    }
                }
                State::Positional => {
                    f("", Some(arg))?;
                    State::Positional
                }
                State::Value { name } => {
                    if arg.starts_with('-') {
                        arg_consumed = false;
                        f(&name, None)?;
                    } else if let Err(e) = f(&name, Some(arg)) {
                        arg_consumed = false;
                        f(&name, None).map_err(|_| e)?;
                    }
                    State::Top
                }
            };

            if arg_consumed {
                break;
            }
        }
    }

    // If we ran out of arguments while parsing the last parameter, which may be either a
    // value parameter or a flag, try to parse it as a flag. This will produce "missing value"
    // error if the parameter is in fact a value parameter, which is the desired outcome.
    match s {
        State::Value { name } => f(&name, None),
        _ => Ok(()),
    }
}

/// Parses the given `args` against the list of know arguments `arg_list` and calls `f` with each
/// present argument and value if required.
///
/// This function guarantees that only valid long argument names from `arg_list` are sent to the
/// callback `f`. It is also guaranteed that if an arg requires a value (i.e.
/// `arg.value.is_some()`), the value will be `Some` in the callbacks arguments. If the callback
/// returns `Err`, this function will end parsing and return that `Err`.
///
/// See the [module level](index.html) example for a usage example.
pub fn set_arguments<I, R, F>(args: I, arg_list: &[Argument], mut f: F) -> Result<()>
where
    I: Iterator<Item = R>,
    R: AsRef<str>,
    F: FnMut(&str, Option<&str>) -> Result<()>,
{
    parse_arguments(args, |name, value| {
        let mut matches = None;
        for arg in arg_list {
            if let Some(short) = arg.short {
                if name.len() == 1 && name.starts_with(short) {
                    if value.is_some() != arg.value.is_some() {
                        return Err(Error::ExpectedValue(short.to_string()));
                    }
                    matches = Some(arg.long);
                }
            }
            if matches.is_none() && arg.long == name {
                if value.is_none() && arg.value_mode == ArgumentValueMode::Required {
                    return Err(Error::ExpectedValue(arg.long.to_owned()));
                }
                if value.is_some() && arg.value_mode == ArgumentValueMode::Disallowed {
                    return Err(Error::UnexpectedValue(arg.long.to_owned()));
                }
                matches = Some(arg.long);
            }
        }
        match matches {
            Some(long) => f(long, value),
            None => Err(Error::UnknownArgument(name.to_owned())),
        }
    })
}

const DEFAULT_COLUMNS: usize = 80;

/// Get the number of columns on a display, with a reasonable default.
fn get_columns() -> usize {
    DEFAULT_COLUMNS
}

/// Poor man's reflowing function for string. This function will unsplit the
/// lines, an empty line splits a paragraph.
fn reflow(s: &str, offset: usize, width: usize) -> String {
    let mut lines: Vec<String> = vec![];
    let mut prev = "";
    let filler = " ".repeat(offset);
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            // Skip the empty line, the paragraph delimiter.
        } else if prev.is_empty() {
            // Start a new paragraph if the previous line was empty.
            lines.push(line.to_string());
        } else if let Some(last) = lines.last_mut() {
            *last += " ";
            *last += line;
        }
        prev = line;
    }
    let mut lines = lines.into_iter().flat_map(|line| {
        let mut output = vec![];
        // Split the line with the last space found, or if the word exceeds
        // length of one line, give up and use the full width.
        let mut line = line.as_str();
        while let Some(s) = line.get(0..width) {
            let offset = s.rfind(" ").unwrap_or(s.len());
            output.push(s[0..offset].to_string());
            line = &line[offset + 1..];
        }
        // Here we should have the remaining part of the line that is less
        // than `width`.
        output.push(line.to_string());

        output
    });
    match lines.next() {
        None => String::new(),
        Some(line) => std::iter::once(line)
            .chain(lines.map(|line| filler.clone() + &line))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Obtain the leading part of the help message. The output is later processed
/// to reflow. Depending on how short this, newline is used.
fn get_leading_part(arg: &Argument) -> String {
    [
        match arg.short {
            Some(s) => format!(" -{}, ", s),
            None => "     ".to_string(),
        },
        if arg.long.is_empty() {
            "  ".to_string()
        } else {
            "--".to_string()
        },
        format!("{:<12}", arg.long),
        if let Some(v) = arg.value {
            format!("{}{:<9} ", if arg.long.is_empty() { " " } else { "=" }, v)
        } else {
            " ".to_string()
        },
    ]
    .join("")
}

/// Prints command line usage information to stdout.
///
/// Usage information is printed according to the help fields in `args` with a leading usage line.
/// The usage line is of the format "`program_name` \[ARGUMENTS\] `required_arg`".
pub fn print_help(program_name: &str, required_arg: &str, args: &[Argument]) {
    println!(
        "Usage: {} {}{}\n",
        program_name,
        if args.is_empty() { "" } else { "[ARGUMENTS] " },
        required_arg
    );
    if args.is_empty() {
        return;
    }

    let indent_depth = 30;
    let minimum_width_of_help = DEFAULT_COLUMNS - 1 - indent_depth;
    let columns = get_columns();
    let columns = minimum_width_of_help.max(columns - indent_depth);

    println!("Argument{}:", if args.len() > 1 { "s" } else { "" });
    for arg in args {
        let leading_part = get_leading_part(arg);
        if leading_part.len() <= indent_depth {
            print!(
                "{}{}",
                leading_part,
                " ".repeat(indent_depth - leading_part.len())
            );
        } else {
            print!("{}\n{}", leading_part, " ".repeat(indent_depth));
        }
        println!("{}", reflow(arg.help, indent_depth, columns));
    }
}

pub fn parse_hex_or_decimal(maybe_hex_string: &str) -> Result<u64> {
    // Parse string starting with 0x as hex and others as numbers.
    if let Some(hex_string) = maybe_hex_string.strip_prefix("0x") {
        u64::from_str_radix(hex_string, 16)
    } else if let Some(hex_string) = maybe_hex_string.strip_prefix("0X") {
        u64::from_str_radix(hex_string, 16)
    } else {
        u64::from_str(maybe_hex_string)
    }
    .map_err(|e| Error::InvalidValue {
        value: maybe_hex_string.to_string(),
        expected: e.to_string(),
    })
}

pub struct KeyValuePair<'a> {
    context: &'a str,
    key: &'a str,
    value: Option<&'a str>,
}

impl<'a> KeyValuePair<'a> {
    fn handle_parse_err<T, E: std::error::Error>(
        &self,
        result: std::result::Result<T, E>,
    ) -> Result<T> {
        result.map_err(|e| {
            self.invalid_value_err(format!(
                "Failed to parse parameter `{}` as {}: {}",
                self.key,
                std::any::type_name::<T>(),
                e
            ))
        })
    }

    pub fn key(&self) -> &'a str {
        self.key
    }

    pub fn value(&self) -> Result<&'a str> {
        self.value.ok_or(Error::ExpectedValue(format!(
            "{}: parameter `{}` requires a value",
            self.context, self.key
        )))
    }

    fn get_numeric<T>(&self, val: &str) -> Result<T>
    where
        T: TryFrom<u64>,
        <T as TryFrom<u64>>::Error: std::error::Error,
    {
        let num = parse_hex_or_decimal(val)?;
        self.handle_parse_err(T::try_from(num))
    }

    pub fn parse_numeric<T>(&self) -> Result<T>
    where
        T: TryFrom<u64>,
        <T as TryFrom<u64>>::Error: std::error::Error,
    {
        let val = self.value()?;
        self.get_numeric(val)
    }

    pub fn key_numeric<T>(&self) -> Result<T>
    where
        T: TryFrom<u64>,
        <T as TryFrom<u64>>::Error: std::error::Error,
    {
        self.get_numeric(self.key())
    }

    #[cfg(test)]
    pub fn parse<T>(&self) -> Result<T>
    where
        T: FromStr,
        <T as FromStr>::Err: std::error::Error,
    {
        self.handle_parse_err(T::from_str(self.value()?))
    }

    pub fn parse_or<T>(&self, default: T) -> Result<T>
    where
        T: FromStr,
        <T as FromStr>::Err: std::error::Error,
    {
        match self.value {
            Some(v) => self.handle_parse_err(T::from_str(v)),
            None => Ok(default),
        }
    }

    pub fn invalid_key_err(&self) -> Error {
        Error::UnknownArgument(format!(
            "{}: Unknown parameter `{}`",
            self.context, self.key
        ))
    }

    pub fn invalid_value_err(&self, description: String) -> Error {
        Error::InvalidValue {
            value: self
                .value
                .expect("invalid value error without value")
                .to_string(),
            expected: format!("{}: {}", self.context, description),
        }
    }
}

/// Parse a string of delimiter-separated key-value options. This is intended to simplify parsing
/// of command-line options that take a bunch of parameters encoded into the argument, e.g. for
/// setting up an emulated hardware device. Returns an Iterator of KeyValuePair, which provides
/// convenience functions to parse numeric values and performs appropriate error handling.
///
/// `flagname` - name of the command line parameter, used as context in error messages
/// `s` - the string to parse
/// `delimiter` - the character that separates individual pairs
///
/// Usage example:
/// ```
/// # use crosvm::argument::{Result, parse_key_value_options};
///
/// fn parse_turbo_button_parameters(s: &str) -> Result<(String, u32, bool)> {
///     let mut color = String::new();
///     let mut speed = 0u32;
///     let mut turbo = false;
///
///     for opt in parse_key_value_options("turbo-button", s, ',') {
///         match opt.key() {
///             "color" => color = opt.value()?.to_string(),
///             "speed" => speed = opt.parse_numeric::<u32>()?,
///             "turbo" => turbo = opt.parse_or::<bool>(true)?,
///             _ => return Err(opt.invalid_key_err()),
///         }
///     }
///
///     Ok((color, speed, turbo))
/// }
///
/// assert_eq!(parse_turbo_button_parameters("color=red,speed=0xff,turbo").unwrap(),
///            ("red".to_string(), 0xff, true))
/// ```
///
/// TODO: upgrade `delimiter` to generic Pattern support once that has been stabilized
/// at <https://github.com/rust-lang/rust/issues/27721>.
pub fn parse_key_value_options<'a>(
    flagname: &'a str,
    s: &'a str,
    delimiter: char,
) -> impl Iterator<Item = KeyValuePair<'a>> {
    s.split(delimiter)
        .map(|frag| frag.splitn(2, '='))
        .map(move |mut kv| KeyValuePair {
            context: flagname,
            key: kv.next().unwrap_or(""),
            value: kv.next(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_help() {
        let arguments = [Argument::short_flag('h', "help", "Print help message.")];

        let match_res = set_arguments(["-h"].iter(), &arguments[..], |name, _| match name {
            "help" => Err(Error::PrintHelp),
            _ => unreachable!(),
        });
        match match_res {
            Err(Error::PrintHelp) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn mixed_args() {
        let arguments = [
            Argument::positional("FILES", "files to operate on"),
            Argument::short_value('p', "program", "PROGRAM", "Program to apply to each file"),
            Argument::short_value('c', "cpus", "N", "Number of CPUs to use. (default: 1)"),
            Argument::flag("unmount", "Unmount the root"),
            Argument::short_flag('h', "help", "Print help message."),
        ];

        let mut unmount = false;
        let match_res = set_arguments(
            ["--cpus", "3", "--program", "hello", "--unmount", "file"].iter(),
            &arguments[..],
            |name, value| {
                match name {
                    "" => assert_eq!(value.unwrap(), "file"),
                    "program" => assert_eq!(value.unwrap(), "hello"),
                    "cpus" => {
                        let c: u32 = value.unwrap().parse().map_err(|_| Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("this value for `cpus` needs to be integer"),
                        })?;
                        assert_eq!(c, 3);
                    }
                    "unmount" => unmount = true,
                    "help" => return Err(Error::PrintHelp),
                    _ => unreachable!(),
                };
                Ok(())
            },
        );
        assert!(match_res.is_ok());
        assert!(unmount);
    }

    #[test]
    fn name_value_pair() {
        let arguments = [Argument::short_value(
            'c',
            "cpus",
            "N",
            "Number of CPUs to use. (default: 1)",
        )];
        let match_res = set_arguments(
            ["-c", "5", "--cpus", "5", "-c5", "--cpus=5"].iter(),
            &arguments[..],
            |name, value| {
                assert_eq!(name, "cpus");
                assert_eq!(value, Some("5"));
                Ok(())
            },
        );
        assert!(match_res.is_ok());
        let not_match_res = set_arguments(
            ["-c", "5", "--cpus"].iter(),
            &arguments[..],
            |name, value| {
                assert_eq!(name, "cpus");
                assert_eq!(value, Some("5"));
                Ok(())
            },
        );
        assert!(not_match_res.is_err());
    }

    #[test]
    fn flag_or_value() {
        let run_case = |args| -> Option<String> {
            let arguments = [
                Argument::positional("FILES", "files to operate on"),
                Argument::flag_or_value("gpu", "[2D|3D]", "Enable or configure gpu"),
                Argument::flag("foo", "Enable foo."),
                Argument::value("bar", "stuff", "Configure bar."),
            ];

            let mut gpu_value: Option<String> = None;
            let match_res =
                set_arguments(args, &arguments[..], |name: &str, value: Option<&str>| {
                    match name {
                        "" => assert_eq!(value.unwrap(), "file1"),
                        "foo" => assert!(value.is_none()),
                        "bar" => assert_eq!(value.unwrap(), "stuff"),
                        "gpu" => match value {
                            Some(v) => match v {
                                "2D" | "3D" => {
                                    gpu_value = Some(v.to_string());
                                }
                                _ => {
                                    return Err(Error::InvalidValue {
                                        value: v.to_string(),
                                        expected: String::from("2D or 3D"),
                                    })
                                }
                            },
                            None => {
                                gpu_value = None;
                            }
                        },
                        _ => unreachable!(),
                    };
                    Ok(())
                });

            assert!(match_res.is_ok());
            gpu_value
        };

        // Used as flag and followed by positional
        assert_eq!(run_case(["--gpu", "file1"].iter()), None);
        // Used as flag and followed by flag
        assert_eq!(run_case(["--gpu", "--foo", "file1",].iter()), None);
        // Used as flag and followed by value
        assert_eq!(run_case(["--gpu", "--bar=stuff", "file1"].iter()), None);

        // Used as value and followed by positional
        assert_eq!(run_case(["--gpu=2D", "file1"].iter()).unwrap(), "2D");
        // Used as value and followed by flag
        assert_eq!(run_case(["--gpu=2D", "--foo"].iter()).unwrap(), "2D");
        // Used as value and followed by value
        assert_eq!(
            run_case(["--gpu=2D", "--bar=stuff", "file1"].iter()).unwrap(),
            "2D"
        );
    }

    #[test]
    fn parse_key_value_options_simple() {
        let mut opts = parse_key_value_options("test", "fruit=apple,number=13,flag,hex=0x123", ',');

        let kv1 = opts.next().unwrap();
        assert_eq!(kv1.key(), "fruit");
        assert_eq!(kv1.value().unwrap(), "apple");

        let kv2 = opts.next().unwrap();
        assert_eq!(kv2.key(), "number");
        assert_eq!(kv2.parse::<u32>().unwrap(), 13);

        let kv3 = opts.next().unwrap();
        assert_eq!(kv3.key(), "flag");
        assert!(kv3.value().is_err());
        assert!(kv3.parse_or::<bool>(true).unwrap());

        let kv4 = opts.next().unwrap();
        assert_eq!(kv4.key(), "hex");
        assert_eq!(kv4.parse_numeric::<u32>().unwrap(), 0x123);

        assert!(opts.next().is_none());
    }

    #[test]
    fn parse_key_value_options_overflow() {
        let mut opts = parse_key_value_options("test", "key=1000000000000000", ',');
        let kv = opts.next().unwrap();
        assert!(kv.parse::<u32>().is_err());
        assert!(kv.parse_numeric::<u32>().is_err());
    }

    #[test]
    fn parse_hex_or_decimal_simple() {
        assert_eq!(parse_hex_or_decimal("15").unwrap(), 15);
        assert_eq!(parse_hex_or_decimal("0x15").unwrap(), 0x15);
        assert_eq!(parse_hex_or_decimal("0X15").unwrap(), 0x15);
        assert!(parse_hex_or_decimal("0xz").is_err());
        assert!(parse_hex_or_decimal("hello world").is_err());
    }

    #[test]
    fn parse_key_value_options_numeric_key() {
        let mut opts = parse_key_value_options("test", "0x30,0x100=value,nonnumeric=value", ',');
        let kv = opts.next().unwrap();
        assert_eq!(kv.key_numeric::<u32>().unwrap(), 0x30);

        let kv = opts.next().unwrap();
        assert_eq!(kv.key_numeric::<u32>().unwrap(), 0x100);
        assert_eq!(kv.value().unwrap(), "value");

        let kv = opts.next().unwrap();
        assert!(kv.key_numeric::<u32>().is_err());
        assert_eq!(kv.key(), "nonnumeric");
    }

    #[test]
    fn reflow_simple() {
        assert_eq!(reflow("Hello world, this is a sample of reflowing operation that should work generally. However I don't know if it is useful", 10, 40),
        "Hello world, this is a sample of
          reflowing operation that should work
          generally. However I don't know if it
          is useful");
    }

    #[test]
    fn reflow_paragraph() {
        assert_eq!(
            reflow(
                "Hello world, this is a sample of reflowing operation that should work generally.

I am going to give you another paragraph. However I don't know if it is useful",
                10,
                40
            ),
            "Hello world, this is a sample of
          reflowing operation that should work
          generally.
          I am going to give you another
          paragraph. However I don't know if it
          is useful"
        );
    }

    #[test]
    fn get_leading_part_short() {
        assert_eq!(
            get_leading_part(&Argument::positional("FILES", "files to operate on")).len(),
            30
        );
        assert_eq!(
            get_leading_part(&Argument::flag_or_value(
                "gpu",
                "[2D|3D]",
                "Enable or configure gpu"
            ))
            .len(),
            30
        );
        assert_eq!(
            get_leading_part(&Argument::flag("foo", "Enable foo.")).len(),
            20
        );
        assert_eq!(
            get_leading_part(&Argument::value("bar", "stuff", "Configure bar.")).len(),
            30
        );
    }

    #[test]
    fn get_leading_part_long() {
        assert_eq!(
            get_leading_part(&Argument::value(
                "very-long-flag-name",
                "stuff",
                "Configure bar."
            ))
            .len(),
            37
        );
    }
}
