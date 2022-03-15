if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150285" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-13 06:10:09 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Deploying LDP Authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_display_mpls_ldp_peer.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "LDP MD5 authentication is deployed to prevent attackers from
attempting to use protocols on the control plane to destroy entries on which forwarding
depends, such as routes." );
	exit( 0 );
}
require("policy_functions.inc.sc");
port = get_kb_item( "huawei/vrp/ssh-login/port" );
model = get_kb_item( "huawei/vrp/ssh-login/" + port + "/model" );
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
cmd = "display mpls ldp session verbose";
title = "Deploying LDP Authentication";
solution = "Deploy LDP MD5 authentication.";
test_type = "SSH_Cmd";
default = "MD5 Flag(s) not off";
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
		if( IsMatchRegexp( model, "^(AR|AC|AP|S)" ) && IsMatchRegexp( major_version, "^5" ) ){
			exit( 0 );
		}
		else {
			if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
				value = "Error";
				compliant = "incomplete";
				comment = "No SSH connection to VRP device.";
			}
			else {
				if( get_kb_item( "Policy/vrp/mpls/ldp/session/ERROR" ) ){
					value = "Error";
					compliant = "incomplete";
					comment = "Can not determine the current mpls ldp session configuration.";
				}
				else {
					mpls_ldp_peer = get_kb_item( "Policy/vrp/mpls/ldp/session" );
					if( IsMatchRegexp( mpls_ldp_peer, "md5\\s+flag\\s+:\\s+off" ) ){
						value = "MD5 Flag off";
						compliant = "no";
						comment = "At least one MD5 Flag is turned off.";
					}
					else {
						value = "MD5 Flag(s) not off";
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

