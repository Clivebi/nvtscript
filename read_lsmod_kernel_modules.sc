if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150111" );
	script_version( "2020-01-30T13:16:16+0000" );
	script_tag( name: "last_modification", value: "2020-01-30 13:16:16 +0000 (Thu, 30 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 15:55:47 +0100 (Wed, 29 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read output of lsmod (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_gnu_bash_detect_lin.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/lsmod" );
	script_tag( name: "summary", value: "lsmod shows the status of modules in the Linux Kernel.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "lsmod";
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/" + cmd + "/ERROR", value: TRUE );
	exit( 0 );
}
ssh_cmd = "/usr/sbin/" + cmd;
lsmod = ssh_cmd( socket: sock, cmd: ssh_cmd, return_error: FALSE );
for line in split( buffer: lsmod, keep: FALSE ) {
	line = ereg_replace( string: line, pattern: "(\\s+)", replace: "|" );
	module = split( buffer: line, sep: "|", keep: FALSE );
	set_kb_item( name: "Policy/linux/module/" + module[0], value: TRUE );
}
exit( 0 );

