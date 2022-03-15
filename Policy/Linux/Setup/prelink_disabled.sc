if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150502" );
	script_version( "2021-03-03T15:26:07+0000" );
	script_tag( name: "last_modification", value: "2021-03-03 15:26:07 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-11 14:04:26 +0000 (Fri, 11 Dec 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Disable prelink" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/prelink" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.5.4 Ensure prelink is disabled (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 14.9 Enforce Detail Logging for Access or Changes to Sensitive Data" );
	script_tag( name: "summary", value: "prelink is a program that modifies ELF shared libraries and ELF dynamically linked
binaries in such a way that the time needed for the dynamic linker to perform relocations
at startup significantly decreases." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "[rpm -q, dpkg -s]  prelink";
title = "Disable prelink";
solution = "Uninstall prelink using the appropriate package manager or manual installation";
test_type = "SSH_Cmd";
default = "Disabled";
if( !get_kb_item( "login/SSH/success" ) ){
	value = "Error";
	compliant = "incomplete";
	note = "No SSH connection possible";
}
else {
	if( version = get_package_version( package: "prelink" ) ){
		value = "Enabled";
		compliant = "no";
	}
	else {
		value = "Disabled";
		compliant = "yes";
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: note );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

