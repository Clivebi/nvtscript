if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109832" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-26 08:11:19 +0100 (Tue, 26 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Duplicated UIDs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "policy_linux_file_content.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 6.2.16 Ensure no duplicate UIDs exist (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 6.2.15 Ensure no duplicate UIDs exist (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16 Account Monitoring and Control" );
	script_tag( name: "summary", value: "Duplicated UIDs can occur after modifiying '/etc/passwd'. Users
with same UIDs are not only granted same privileges, but they are considered as the same person.

This script tests if any duplicated UIDs are listed in '/etc/passwd'." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "cat /etc/passwd | cut -d: -f1,3";
title = "No duplicated UIDs";
solution = "Assign new UIDs for duplicated user. Check files and directories owned by the user.";
test_type = "SSH_Cmd";
default = "None";
if( get_kb_item( "policy/linux/file_content/error" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( !content = get_kb_item( "Policy/linux//etc/passwd/content" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/passwd";
	}
	else {
		uids_array = make_array();
		for line in split( buffer: content, keep: FALSE ) {
			fields = split( buffer: line, sep: ":", keep: FALSE );
			user_name = fields[0];
			uid = fields[2];
			if( uids_array[uid] ){
				value += ", " + uid + ": " + user_name + " " + uids_array[uid];
			}
			else {
				uids_array[uid] = user_name;
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

