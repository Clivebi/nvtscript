if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150148" );
	script_version( "2020-06-16T13:26:24+0000" );
	script_tag( name: "last_modification", value: "2020-06-16 13:26:24 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-03-09 12:37:56 +0000 (Mon, 09 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Content of DB_USER_SYS_PRIVS database" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "This script writes the complete database of DB_USER_SYS_PRIVS to KB.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/zsql/zsql_db_user_sys_privs/ssh/ERROR", value: TRUE );
	exit( 0 );
}
query = "dump table DB_USER_SYS_PRIVS into file \'STDOUT\' COLUMNS TERMINATED BY \'|\';";
db_user_sys_privs = zsql_command( socket: sock, query: query );
if(!db_user_sys_privs){
	set_kb_item( name: "Policy/zsql/zsql_db_user_sys_privs/ERROR", value: TRUE );
}
for line in split( buffer: db_user_sys_privs, keep: FALSE ) {
	if(IsMatchRegexp( line, "SQL>" )){
		line = str_replace( string: line, find: "SQL> ", replace: "" );
	}
	items = eregmatch( string: line, pattern: "(.*)\\|(.*)\\|(.*)" );
	if( items ){
		set_kb_item( name: "Policy/zsql/zsql_db_user_sys_privs/" + items[1] + "/" + items[2], value: items[3] );
	}
	else {
		set_kb_item( name: "Policy/zsql/zsql_db_user_sys_privs/empty", value: TRUE );
	}
}
exit( 0 );

