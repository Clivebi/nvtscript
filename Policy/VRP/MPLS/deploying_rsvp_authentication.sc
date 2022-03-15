if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150286" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-13 10:44:31 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Deploying RSVP Authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_display_mpls_rsvp_te_interface.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "RSVP MD5 authentication is deployed to prevent attackers from
attempting to use protocols on the control plane to destroy entries on which forwarding
depends, such as routes." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
require("list_array_func.inc.sc");
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
cmd = "display mpls rsvp-te interface; display current-configuration interface xxx";
title = "Deploying RSVP Authentication";
solution = "Deploy RSVP MD5 authentication.";
test_type = "SSH_Cmd";
default = "mpls rsvp-te authentication cipher enabled for all mpls rsvp-te interfaces";
if( get_kb_item( "Policy/vrp/installed/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No VRP device detected.";
}
else {
	if( !major_version ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not determine version of VRP device.";
	}
	else {
		if( !IsMatchRegexp( major_version, "^8" ) ){
			exit( 0 );
		}
		else {
			if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
				value = "Error";
				compliant = "incomplete";
				comment = "No SSH connection to VRP device.";
			}
			else {
				if( get_kb_item( "Policy/vrp/mpls/rsvp-te/interface/empty" ) ){
					value = "None";
					compliant = "yes";
					comment = "No mpls rsvp-te interfaces detected.";
				}
				else {
					mpls_interfaces = get_kb_item( "Policy/vrp/mpls/rsvp-te/interface" );
					interface_grep = egrep( string: mpls_interfaces, pattern: "Interface: " );
					if( !interface_grep ){
						value = "None";
						compliant = "yes";
						comment = "No mpls rsvp-te interfaces detected.";
					}
					else {
						for interface in split( buffer: interface_grep, keep: FALSE ) {
							interfaces_name = eregmatch( string: interface, pattern: "Interface:\\s+([A-Z,a-z,0-9,/,_,-]+)" );
							if(!sock = ssh_login_or_reuse_connection()){
								value = "Error";
								compliant = "incomplete";
								comment = "No SSH connection to host";
								break;
							}
							cmd = "display current-configuration interface " + interfaces_name[1];
							ret = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
							if(!IsMatchRegexp( ret, "mpls rsvp-te authentication cipher" )){
								value = "mpls rsvp-te authentication cipher not enabled for all mpls rsvp-te interfaces";
								compliant = "no";
								comment += interfaces_name[1] + " ";
							}
						}
						if(!value){
							value = "mpls rsvp-te authentication cipher enabled for all mpls rsvp-te interfaces";
							compliant = "yes";
						}
					}
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

