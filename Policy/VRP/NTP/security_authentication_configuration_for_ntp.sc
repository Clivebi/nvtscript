if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150293" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-13 14:22:23 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Security authentication configuration for NTP clients and level-2 or multi-level servers" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration_ntp.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Configure security verification for the NTP client and level-2
or multi-level servers." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
port = get_kb_item( "huawei/vrp/ssh-login/port" );
model = get_kb_item( "huawei/vrp/ssh-login/" + port + "/model" );
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
cmd = "display current-configuration | include ntp";
title = "Configuring NTP Client Security Authentication";
solution = "Configure security verification for the NTP client.";
test_type = "SSH_Cmd";
default = "Enabled";
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
			if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
				value = "Error";
				compliant = "incomplete";
				comment = "No SSH connection to VRP device.";
			}
			else {
				if( get_kb_item( "Policy/vrp/current_configuration/ntp/disabled" ) ){
					value = "Not applicable";
					compliant = "yes";
					comment = "This check is applicable if NTP is enabled only, but the command did not return anything.";
				}
				else {
					if( !current_configuration = get_kb_item( "Policy/vrp/current_configuration/ntp" ) ){
						value = "Error";
						compliant = "incomplete";
						comment = "Can not determine the current configuration for ntp.";
					}
					else {
						if( !IsMatchRegexp( current_configuration, "ntp" ) ){
							value = "Not applicable";
							compliant = "yes";
							comment = "This check is applicable if NTP is enabled only. Did not find 'ntp' included in current-configuration.";
						}
						else {
							if( !IsMatchRegexp( current_configuration, "ntp-service\\s+authentication-keyid" ) || !IsMatchRegexp( current_configuration, "ntp-service\\s+authentication\\s+enable" ) || !IsMatchRegexp( current_configuration, "ntp-service\\s+reliable\\s+authentication-keyid" ) ){
								value = "Not applicable";
								compliant = "yes";
								comment = "This check is applicable if following settings are configured: ntp-service authentication-keyid,";
								comment += " ntp-service authentication enable and ntp-service reliable authentication-keyid.";
							}
							else {
								if( IsMatchRegexp( current_configuration, "ntp-service\\s+unicast-server\\s+[a-z,A-Z,0-9,:,., ]+\\s+authentication-keyid" ) ) {
									value = "Enabled";
								}
								else {
									value = "Disabled";
								}
								compliant = policy_setting_exact_match( value: value, set_point: default );
							}
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

