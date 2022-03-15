if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150290" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-13 13:46:56 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring VRRP Authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_display_vrrp.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "VRRP security policies are configured to prevent network attacks." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "display vrrp";
title = "Configuring VRRP Authentication";
solution = "On a network that has strict security requirements, you can configure VRRP security
policies to prevent network attacks.";
test_type = "SSH_Cmd";
default = "Enable";
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
		if( get_kb_item( "Policy/vrp/vrrp/ERROR" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Can not determine the current vrrp configuration.";
		}
		else {
			vrrp = get_kb_item( "Policy/vrp/vrrp" );
			if( !vrrp || IsMatchRegexp( vrrp, "vrrp\\s+does\\s+not\\s+exist" ) || IsMatchRegexp( vrrp, "no\\s+vrrp" ) ){
				value = "VRRP does not exist";
				compliant = "yes";
			}
			else {
				if( !IsMatchRegexp( vrrp, "auth\\s+type" ) || IsMatchRegexp( vrrp, "auth\\s+type\\s+:\\s+md5" ) || IsMatchRegexp( vrrp, "auth\\s+type\\s+:\\s+none" ) ) {
					value = "Disable";
				}
				else {
					value = "Enable";
				}
				compliant = policy_setting_exact_match( value: value, set_point: default );
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

