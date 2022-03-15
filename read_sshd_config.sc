if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150065" );
	script_version( "2021-01-19T14:43:34+0000" );
	script_tag( name: "last_modification", value: "2021-01-19 14:43:34 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-01-13 14:24:40 +0100 (Mon, 13 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read SSHd configuration (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sshd_config" );
	script_tag( name: "summary", value: "sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/sshd_config/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux/sshd_config/stat/ERROR", value: TRUE );
	exit( 0 );
}
stat_cmd = "stat /etc/ssh/sshd_config";
stat_ret = ssh_cmd( socket: sock, cmd: stat_cmd, return_erros: FALSE );
if(!stat_ret){
	set_kb_item( name: "Policy/linux/sshd_config/stat/ERROR", value: TRUE );
	exit( 0 );
}
set_kb_item( name: "Policy/linux/sshd_config/stat", value: stat_ret );
cat_cmd = "cat /etc/ssh/sshd_config";
cat_ret = ssh_cmd( socket: sock, cmd: cat_cmd, return_erros: FALSE );
if(!cat_ret){
	set_kb_item( name: "Policy/linux/sshd_config/ERROR", value: TRUE );
	exit( 0 );
}
set_kb_item( name: "Policy/linux/sshd_config", value: cat_ret );
ret_split = split( buffer: cat_ret, keep: FALSE );
for line in ret_split {
	if(IsMatchRegexp( line, "^\\s*#" ) || IsMatchRegexp( line, "^\\s*$" )){
		continue;
	}
	line = ereg_replace( string: line, pattern: "\\s+", replace: " " );
	replace_first_whitespace = str_replace( string: line, find: " ", replace: "|", count: 1 );
	reg_match = eregmatch( string: replace_first_whitespace, pattern: "(.*)\\|(.*)" );
	set_kb_item( name: "Policy/linux/sshd_config/" + tolower( reg_match[1] ), value: reg_match[2] );
}
policy_access_permission_regex( filepath: "/etc/ssh/ssh_host_*_key", socket: sock );
policy_access_permission_regex( filepath: "/etc/ssh/ssh_host_*_key.pub", socket: sock );
exit( 0 );

