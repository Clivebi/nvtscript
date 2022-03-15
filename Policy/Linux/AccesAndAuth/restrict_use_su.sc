if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109809" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-13 08:35:57 +0100 (Wed, 13 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Restrict users for su command" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_pamd.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "User list (semi-colon separated)", type: "entry", value: "root", id: 1 );
	script_xref( name: "URL", value: "http://www.man7.org/linux/man-pages/man1/su.1.html" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 5.6 Ensure access to the su command is restricted (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 5.7 Ensure access to the su command is restricted (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_tag( name: "summary", value: "su allows to run commands with a substitute user and group ID.

When called with no user specified, su defaults to running an interactive shell as root. When user
is specified, additional arguments can be supplied, in which case they are passed to the shell.

With adding 'auth required pam_wheel.so use_uid' to /etc/pam.d/su only members of the administrative
group wheel can use the su command." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep '^\\s+auth\\s+required\\s+pam_wheel.so\\s+use_uid' /etc/pam.d/su";
title = "Restrict the use of su";
solution = "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su";
test_type = "SSH_Cmd";
default = "Yes";
if( !content = get_kb_item( "Policy/linux//etc/pam.d/su/content" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not read /etc/pam.d/su";
}
else {
	match = egrep( string: content, pattern: "^\\s*auth\\s*required\\s*pam_wheel.so\\s*use_uid" );
	if( match ) {
		value = "Yes";
	}
	else {
		value = "No";
	}
	compliant = policy_setting_exact_match( value: value, set_point: default );
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

