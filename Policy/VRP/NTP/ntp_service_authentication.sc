if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150292" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-13 14:18:03 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: NTP Level-1 Server Security Authentication Configuration" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration_ntp.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Configure the NTP level-1 server security authentication." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "display current-configuration | include ntp";
title = "Configuring NTP Server Security Authentication";
solution = "Configure security verification for the NTP server.";
test_type = "SSH_Cmd";
default = "Enabled";
if( get_kb_item( "Policy/vrp/installed/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No VRP device detected.";
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
					if( IsMatchRegexp( current_configuration, "ntp(-service)?\\s+server\\s+disable" ) && IsMatchRegexp( current_configuration, "ntp(-service)?\\s+ipv6\\s+server\\s+disable" ) ){
						value = "Not applicable";
						compliant = "yes";
						comment = "This check is applicable if device function as a server.";
					}
					else {
						if( !IsMatchRegexp( current_configuration, "ntp(-service)?\\s+authentication\\s+enable" ) || !IsMatchRegexp( current_configuration, "ntp(-service)?\\s+authentication-keyid" ) ){
							compliant = "no";
							value = "Disabled";
							comment = "ntp-service authentication enable not found in current-configuration.";
						}
						else {
							compliant = "yes";
							value = "Enabled";
							comment = "ntp-service authentication enable found in current-configuration.";
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

