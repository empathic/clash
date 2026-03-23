use clap::CommandFactory;

fn get_help(cmd: &clap::Command) -> String {
    cmd.clone().render_help().to_string()
}

fn get_subcommand_help(name: &str) -> String {
    let cmd = clash::cli::Cli::command();
    let sub = cmd
        .find_subcommand(name)
        .unwrap_or_else(|| panic!("subcommand {name} not found"));
    get_help(sub)
}

#[test]
fn help_main() {
    let cmd = clash::cli::Cli::command();
    insta::assert_snapshot!(get_help(&cmd));
}

#[test]
fn help_init() {
    insta::assert_snapshot!(get_subcommand_help("init"));
}

#[test]
fn help_uninstall() {
    insta::assert_snapshot!(get_subcommand_help("uninstall"));
}

#[test]
fn help_status() {
    insta::assert_snapshot!(get_subcommand_help("status"));
}

#[test]
fn help_policy() {
    insta::assert_snapshot!(get_subcommand_help("policy"));
}

#[test]
fn help_sandbox() {
    insta::assert_snapshot!(get_subcommand_help("sandbox"));
}

#[test]
fn help_doctor() {
    insta::assert_snapshot!(get_subcommand_help("doctor"));
}

#[test]
fn help_debug() {
    insta::assert_snapshot!(get_subcommand_help("debug"));
}

#[test]
fn help_trace() {
    insta::assert_snapshot!(get_subcommand_help("trace"));
}

#[test]
fn help_session() {
    insta::assert_snapshot!(get_subcommand_help("session"));
}

#[test]
fn help_fmt() {
    insta::assert_snapshot!(get_subcommand_help("fmt"));
}

#[test]
fn help_explain() {
    insta::assert_snapshot!(get_subcommand_help("explain"));
}

#[test]
fn help_update() {
    insta::assert_snapshot!(get_subcommand_help("update"));
}

#[test]
fn help_shell() {
    insta::assert_snapshot!(get_subcommand_help("shell"));
}

#[test]
fn help_statusline() {
    insta::assert_snapshot!(get_subcommand_help("statusline"));
}
