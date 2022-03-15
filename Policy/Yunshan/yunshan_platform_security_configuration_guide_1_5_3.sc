if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150688" );
	script_version( "2021-09-16T08:25:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:25:11 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 06:36:35 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configure ACLs when the STelnet service is enabled" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Configure ACLs for attack defense." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd1 = "display ssh server status";
cmd2 = "display current-configuration | include ssh";
cmd3 = "display current-configuration | section include user-interface vty";
cmd = cmd1 + "\n" + cmd2 + "\n" + cmd3;
title = "Configure ACLs when the STelnet service is enabled";
solution = "Configure ACLs for attack defense.";
test_type = "SSH_Cmd";
default = "STelnet IPv4 server or STelnet IPv6 server is enabled.
ssh server acl and ssh ipv6 server acl commands exist.
acl and acl ipv6 commands exist in the user-interface vty view.";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value1 = ssh_cmd( socket: sock, cmd: cmd1, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Command '" + cmd1 + "' did not return anything";
	}
	else {
		if( !value2 = ssh_cmd( socket: sock, cmd: cmd2, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
			compliant = "incomplete";
			value = "error";
			comment = "Command '" + cmd2 + "' did not return anything";
		}
		else {
			if( !value3 = ssh_cmd( socket: sock, cmd: cmd3, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
				compliant = "incomplete";
				value = "error";
				comment = "Command '" + cmd3 + "' did not return anything";
			}
			else {
				if( IsMatchRegexp( value1, "-----More----" ) || IsMatchRegexp( value2, "----More----" ) || IsMatchRegexp( value3, "----More----" ) ){
					compliant = "incomplete";
					value = "error";
					comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
				}
				else {
					value = cmd1 + ":\n" + value1;
					value += "\n\n" + cmd2 + ":\n" + value2;
					value += "\n\n" + cmd3 + ":\n" + value3;
					if(!IsMatchRegexp( value1, "STelnet\\s+IPv4\\s+server\\s*:\\s*Enable" ) && !IsMatchRegexp( value1, "STelnet\\s+IPv6\\s+server\\s*:\\s*Enable" )){
						compliant = "no";
						comment = "STelnet is not enabled.";
					}
					if(!IsMatchRegexp( value2, "ssh\\s+server\\s+acl" ) || !IsMatchRegexp( value2, "ssh\\s+ipv6\\s+server\\s+acl" )){
						compliant = "no";
						comment = "ssh server or ssh ipv6 server acl is not enabled.";
					}
					if(!IsMatchRegexp( value3, "acl" ) || !IsMatchRegexp( value3, "acl\\s+ipv6" )){
						compliant = "no";
						comment = "acl and acl ipv6 is not enabled in user-interface vty view.";
					}
					if(!compliant){
						compliant = "yes";
					}
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

