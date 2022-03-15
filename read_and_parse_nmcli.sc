if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150181" );
	script_version( "2020-07-29T11:15:13+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 11:15:13 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-25 09:23:14 +0000 (Wed, 25 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Get network devices (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/1/nmcli" );
	script_tag( name: "summary", value: "nmcli is a command-line tool for controlling NetworkManager and
getting its status. It is not meant as a replacement of nm-applet or other similar clients. Rather
it's a complementary utility to these programs. The main nmcli's usage is on servers, headless
machines or just for power users who prefer the command line.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/nmcli/ssh/ERROR", value: TRUE );
	exit( 0 );
}
cmd = "nmcli -t -c no device 2>/dev/null";
ret = ssh_cmd_without_errors( socket: sock, cmd: cmd );
if(!ret){
	set_kb_item( name: "Policy/linux/nmcli/ERROR", value: TRUE );
	exit( 0 );
}
for row in split( buffer: ret, keep: FALSE ) {
	match = eregmatch( string: chomp( row ), pattern: "([^:]+):([^:]+):([^:]+):([^:]*)" );
	if(match){
		set_kb_item( name: "Policy/linux/nmcli/devices", value: match[1] );
		set_kb_item( name: "Policy/linux/nmcli/" + match[1] + "/type", value: match[2] );
		set_kb_item( name: "Policy/linux/nmcli/" + match[1] + "/state", value: match[3] );
		if( match[4] ) {
			set_kb_item( name: "Policy/linux/nmcli/" + match[1] + "/connection", value: match[4] );
		}
		else {
			set_kb_item( name: "Policy/linux/nmcli/" + match[1] + "/connection/ERROR", value: TRUE );
		}
	}
}
exit( 0 );

