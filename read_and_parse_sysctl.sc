if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150141" );
	script_version( "2020-07-29T11:15:13+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 11:15:13 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-24 08:28:11 +0000 (Mon, 24 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read sysctl variables (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/sysctl" );
	script_tag( name: "summary", value: "sysctl is used to modify kernel parameters at runtime. The
parameters available are those listed under /proc/sys/. Procfs is required for sysctl support in
Linux. You can use sysctl to both read and write sysctl data.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/sysctl/ssh/ERROR", value: TRUE );
	exit( 0 );
}
cmd = "/sbin/sysctl -a 2>/dev/null";
ret = ssh_cmd_without_errors( socket: sock, cmd: cmd );
if(!ret){
	set_kb_item( name: "Policy/linux/sysctl/ERROR", value: TRUE );
	exit( 0 );
}
for row in split( buffer: ret, keep: FALSE ) {
	match = eregmatch( string: row, pattern: "([^=]+)\\s*=\\s*(.+)" );
	if(match){
		set_kb_item( name: "Policy/linux/sysctl/" + chomp( match[1] ), value: chomp( match[2] ) );
	}
}
exit( 0 );

