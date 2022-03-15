if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150143" );
	script_version( "2020-07-29T11:15:13+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 11:15:13 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-24 13:26:55 +0000 (Mon, 24 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read pam_limits module config files (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/limits.conf" );
	script_tag( name: "summary", value: "The pam_limits.so module applies ulimit limits, nice priority
and number of simultaneous login sessions limit to user login sessions. This description of the
configuration file syntax applies to the /etc/security/limits.conf file and *.conf files in the
/etc/security/limits.d directory.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/security/limits/conf/ERROR", value: TRUE );
	exit( 0 );
}
policy_linux_stat_file( socket: sock, file: "/etc/security/limits.conf" );
policy_linux_file_content( socket: sock, file: "/etc/security/limits.conf" );
policy_read_files_in_directory( socket: sock, directory: "/etc/security/limits.d/" );
exit( 0 );

