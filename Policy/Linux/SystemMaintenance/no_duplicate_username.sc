if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109834" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-26 10:35:08 +0100 (Tue, 26 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Duplicated user names" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "policy_linux_file_content.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 6.2.18 Ensure no duplicate user names exist (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 6.2.17 Ensure no duplicate user names exist (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16 Account Monitoring and Control" );
	script_tag( name: "summary", value: "Duplicated user names can be created with modify '/etc/passwd'.
When logging in, the first found UID is used for that user leading to a shared UID.

This script tests if duplicated user names are listed in '/etc/passwd'." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("list_array_func.inc.sc");
cmd = "cut -f1 -d\":\" /etc/passwd | sort -n | uniq -c | while read x ; do
  [ -z \"$x\" ] && break
  set - $x
  if [ $1 -gt 1 ]; then
    uids=$(awk -F: \'($1 == n) { print $3 }\' n=$2 /etc/passwd | xargs)
    echo \"Duplicate User Name ($2)\"
  fi
done";
title = "No duplicate user names";
solution = "Based on the results of the audit script, establish unique user names for the users. File
ownerships will automatically reflect the change as long as the users have unique UIDs.";
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
		user_names = make_list();
		for line in split( buffer: content, keep: FALSE ) {
			fields = split( buffer: line, sep: ":", keep: FALSE );
			user = fields[0];
			if( !in_array( search: user, array: user_names, part_match: FALSE, icase: FALSE ) ){
				user_names = make_list( user_names,
					 user );
			}
			else {
				value = "Duplicate User Name " + user + "\n";
			}
		}
		if( value ){
			value = chomp( value );
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

