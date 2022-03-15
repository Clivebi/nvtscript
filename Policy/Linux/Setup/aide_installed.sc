if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150180" );
	script_version( "2021-05-14T14:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 14:03:39 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2020-03-24 12:48:23 +0000 (Tue, 24 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Install AIDE" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/1/aide" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.3.1 Ensure AIDE is installed (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 1.4.1 Ensure AIDE is installed (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 14.9 Enforce Detail Logging for Access or Changes to Sensitive Data" );
	script_tag( name: "summary", value: "Advanced Intrusion Detection Environment (aide) is an intrusion
detection system for checking the integrity of files." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "[rpm -q, dpkg -s] aide";
title = "Install AIDE";
solution = "Install package 'aide'";
test_type = "SSH_Cmd";
default = "Installed";
if( !get_kb_item( "login/SSH/success" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	installed = get_package_version( package: "aide" );
	if( !installed ) {
		value = "Not installed";
	}
	else {
		value = "Installed";
	}
	compliant = policy_setting_exact_match( value: value, set_point: default );
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

