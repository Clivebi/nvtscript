if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109824" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-20 11:15:07 +0100 (Wed, 20 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Only root user has UID 0" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_mandatory_keys( "Compliance/Launch" );
	script_dependencies( "policy_linux_file_content.sc" );
	script_xref( name: "URL", value: "https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 6.2.5 Ensure root is the only UID 0 account (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 6.2.6 Ensure root is the only UID 0 account (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_tag( name: "summary", value: "The UID 0 refers to an account with superuser privileges.
Limiting the UID 0 to root user only prevents other users from unauthorized access rights.

This script tests if any other user than root has UID 0." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'";
title = "Only root user has UID 0";
solution = "Remove users with UID 0 or assign new UID";
test_type = "SSH_Cmd";
default = "None";
if( get_kb_item( "policy/linux/file_content/error" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/passwd/content/ERROR" ) || !content = get_kb_item( "Policy/linux//etc/passwd/content" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Error reading file /etc/passwd";
	}
	else {
		for line in split( buffer: content, keep: FALSE ) {
			fields = split( buffer: line, sep: ":", keep: FALSE );
			if(fields[0] == "root"){
				continue;
			}
			if(fields[2] == "0"){
				value += ", " + fields[0];
			}
		}
		if( value ){
			value = str_replace( string: value, find: ", ", replace: "", count: 1 );
			compliant = "no";
		}
		else {
			value = "None";
			compliant = "yes";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

