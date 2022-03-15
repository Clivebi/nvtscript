if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150689" );
	script_version( "2021-10-01T13:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 13:03:39 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 06:36:35 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Disabling the FTP Service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "The FTP protocol is insecure. If the FTP service is not used,
  disable it." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "display ftp server";
title = "Disabling the FTP Service";
solution = "Run the undo ftp server and undo ftp ipv6 server commands to disable the FTP service.";
test_type = "SSH_Cmd";
default = "Server state: Enabled and IPv6 server state: Enabled";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
		compliant = "yes";
		value = "None";
		comment = "Command '" + cmd + "' did not return anything";
	}
	else {
		if( IsMatchRegexp( value, "-----More----" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
		}
		else {
			if( IsMatchRegexp( value, "server\\s+state\\s*:\\s*enabled" ) ){
				compliant = "no";
			}
			else {
				compliant = "yes";
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

