if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150246" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: FTP Server Status" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_ftp_server_status.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "The FTP protocol is insecure. If the FTP service is not used, disable
it." );
	exit( 0 );
}
require("policy_functions.inc.sc");
port = get_kb_item( "huawei/vrp/ssh-login/port" );
model = get_kb_item( "huawei/vrp/ssh-login/" + port + "/model" );
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
cmd = "display ftp-server";
title = "Disabling the FTP Service";
solution = "Run the undo ftp server and undo ftp ipv6 server commands to disable the FTP service.";
test_type = "SSH_Cmd";
default = "Disable";
if( get_kb_item( "Policy/vrp/installed/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No VRP device detected.";
}
else {
	if( !model || !major_version ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not determine model or version of VRP device.";
	}
	else {
		if( IsMatchRegexp( model, "^CE" ) && IsMatchRegexp( major_version, "^8" ) ){
			exit( 0 );
		}
		else {
			if( IsMatchRegexp( model, "^(CE|AR|S)" ) && IsMatchRegexp( major_version, "^5" ) ){
				exit( 0 );
			}
			else {
				if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
					value = "Error";
					compliant = "incomplete";
					comment = "No SSH connection to VRP device.";
				}
				else {
					if( get_kb_item( "Policy/vrp/ftpserver/ERROR" ) ){
						value = "Error";
						compliant = "incomplete";
						comment = "Can not determine the current FTP service status.";
					}
					else {
						ftp_server = get_kb_item( "Policy/vrp/ftpserver/serverstate" );
						ftp_ipv6server = get_kb_item( "Policy/vrp/ftpserver/ipv6serverstate" );
						if( ftp_server == "Enabled" || ftp_ipv6server == "Enabled" ) {
							value = "Enable";
						}
						else {
							value = "Disable";
						}
						compliant = policy_setting_exact_match( value: value, set_point: default );
					}
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

