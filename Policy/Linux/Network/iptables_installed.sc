if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150179" );
	script_version( "2021-03-03T15:26:07+0000" );
	script_tag( name: "last_modification", value: "2021-03-03 15:26:07 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-03-24 10:05:37 +0000 (Tue, 24 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Install iptables" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/iptables" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 3.5.3 Ensure iptables is installed (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 9.4 Apply Host-based Firewalls or Port Filtering" );
	script_tag( name: "summary", value: "Iptables is used to set up, maintain, and inspect the tables of
IP packet filter rules in the Linux kernel." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "[rpm -q, dpkg -s] iptables";
title = "Install iptables";
solution = "Install package 'iptables'";
test_type = "SSH_Cmd";
default = "Installed";
if( !get_kb_item( "login/SSH/success" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	iptables_installed = get_package_version( package: "iptables" );
	if( !iptables_installed ) {
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

