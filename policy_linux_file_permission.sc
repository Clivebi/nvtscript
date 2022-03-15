if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150574" );
	script_version( "2021-01-25T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-01-25 13:01:30 +0000 (Mon, 25 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-25 11:23:31 +0000 (Mon, 25 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Get access permissions to configuration files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Get access permissions to relevant Linux config files like
/etc/shadow, /etc/passwd and other." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "policy/linux/access_permissions/error", value: TRUE );
	exit( 0 );
}
files = "/etc/shadow
/etc/passwd
/etc/group
/etc/gshadow
/etc/passwd-
/etc/shadow-
/etc/group-
/etc/gshadow-
";
policy_access_permission_regex( filepath: files, socket: sock );
exit( 0 );

