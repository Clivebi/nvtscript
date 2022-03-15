if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150576" );
	script_version( "2021-01-27T15:10:53+0000" );
	script_tag( name: "last_modification", value: "2021-01-27 15:10:53 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-27 14:44:55 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Get content of configuration files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Get content of relevant Linux config files like /etc/shadow,
/etc/passwd and other" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "policy/linux/file_content/error", value: TRUE );
	exit( 0 );
}
files = make_list( "/etc/passwd",
	 "/etc/shadow",
	 "/etc/group" );
for file in files {
	policy_linux_file_content( socket: sock, file: file );
}
exit( 0 );

