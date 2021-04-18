use std::path::PathBuf;
use structopt::StructOpt;
use anyhow::Result;
use shellkey_authd::ssh::{SshConfig, parse_identities};
use std::os::unix::net::UnixListener;

/// SSH authentication daemon for ShellKey.
#[derive(StructOpt, Debug)]
#[structopt(name = "skauthd")]
struct Opt {
  /// Server URL.
  #[structopt(short, long)]
  server: String,

  /// Path to the identity file.
  #[structopt(short, long, parse(from_os_str))]
  identities: PathBuf,

  /// Listen path.
  #[structopt(short, long, parse(from_os_str))]
  listen: PathBuf,
}

fn main() -> Result<()> {
  pretty_env_logger::init_timed();

  let opt = Opt::from_args();
  let identities = parse_identities(&std::fs::read_to_string(&opt.identities)?)?;
  let ssh_config = SshConfig {
    identities,
    api_prefix: opt.server,
  };
  shellkey_authd::ssh::set_config(ssh_config);

  let _ = std::fs::remove_file(&opt.listen);
  let listener = UnixListener::bind(&opt.listen)?;
  ssh_agent::Agent::run(shellkey_authd::ssh::Handler, listener);
  panic!("SSH agent exited");
}
