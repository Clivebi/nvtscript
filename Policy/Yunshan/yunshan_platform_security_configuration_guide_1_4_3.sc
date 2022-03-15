if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150685" );
	script_version( "2021-09-16T08:25:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:25:11 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 11:41:38 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: local-user service-type all or both secure and insecure protocols" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "When a user account uses both secure and insecure protocols,
  the insecure protocols will cause password disclosure." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "display current-configuration configuration aaa";
title = "local-user service-type all or both secure and insecure protocols";
solution = "Each user supports only one service type.";
test_type = "SSH_Cmd";
default = "If 'local-user username service-type' all or multiple service types exist, security risks exist";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Command '" + cmd + "' did not return anything";
	}
	else {
		if( IsMatchRegexp( value, "-----More----" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
		}
		else {
			if( IsMatchRegexp( !value, "local-user\\s+[^@[:space:]]+\\s+service-type" ) ){
				compliant = "incomplete";
				comment = "No 'local-user username service-type' found in command return.";
			}
			else {
				service_type_line = egrep( string: value, pattern: "service-type" );
				if(service_type_line){
					service_types = eregmatch( string: service_type_line, pattern: "local-user\\s+[^@[:space:]]+\\s+service-type\\s+(.+)" );
					if(service_types){
						if( IsMatchRegexp( service_types[1], "all" ) ) {
							compliant = "no";
						}
						else {
							if(max_index( split( buffer: service_types[1], sep: " ", keep: FALSE ) ) > 1){
								compliant = "no";
							}
						}
					}
				}
				if(!compliant){
					compliant = "yes";
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

