if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150692" );
	script_version( "2021-09-16T08:25:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:25:11 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 06:36:35 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring Community Name Complexity Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "If SNMPv1 and SNMPv2 are used, the community complexity check function must be enabled." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd1 = "display snmp-agent sys-info version";
cmd2 = "display snmp-agent sys-info version";
cmd = cmd1 + "\n" + cmd2;
title = "Configuring Community Name Complexity Check";
solution = "Run the undo snmp-agent community complexity-check disable command to enable the community complexity check function.";
test_type = "SSH_Cmd";
default = "If SNMPv1 or SNMPv2 is enabled, 'snmp-agent community complexity-check' should be enabled.";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = ssh_cmd( socket: sock, cmd: cmd1, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Command '" + cmd1 + "' did not return anything";
	}
	else {
		if( IsMatchRegexp( value, "-----More----" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
		}
		else {
			if( IsMatchRegexp( value, "(SNMPv1|SNMPv2)" ) ){
				if( !value2 = ssh_cmd( socket: sock, cmd: cmd2, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
					compliant = "incomplete";
					value = "error";
					comment = "Command '" + cmd2 + "' did not return anything";
				}
				else {
					if( IsMatchRegexp( value2, "-----More----" ) ){
						compliant = "incomplete";
						value = "error";
						comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
					}
					else {
						value += "\n\n" + value2;
						if( IsMatchRegexp( value2, "snmp-agent\\s+community\\s+complexity-check\\s+disable" ) && !IsMatchRegexp( value2, "undo\\s+snmp-agent\\s+community\\s+complexity-check\\s+disable" ) ){
							compliant = "no";
						}
						else {
							compliant = "yes";
						}
					}
				}
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

