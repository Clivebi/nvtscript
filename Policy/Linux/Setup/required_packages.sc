if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150086" );
	script_version( "2020-07-29T07:27:10+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 07:27:10 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-20 09:10:10 +0100 (Mon, 20 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Required Packages" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_add_preference( name: "Value", type: "entry", value: "tcpd", id: 1 );
	script_tag( name: "summary", value: "This script checks if all of the given packages are installed
on the host." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "[rpm -q, dpkg -s] PACKAGE";
title = "Required Packages";
solution = "Install packages";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( !get_kb_item( "login/SSH/success" ) ){
	value = "Error";
	compliant = "incomplete";
	note = "No SSH connection possible";
}
else {
	package_list = split( buffer: default, sep: ",", keep: FALSE );
	for package in package_list {
		version = get_package_version( package: package );
		if(!version){
			value += "," + package;
		}
	}
	if( value ){
		value = str_replace( string: value, find: ",", replace: "", count: 1 );
		compliant = "no";
	}
	else {
		compliant = "yes";
		value = "None";
	}
	note = "'Actual Value' show missing packages.";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: note );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

