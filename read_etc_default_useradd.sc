if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150135" );
	script_version( "2020-07-29T11:15:13+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 11:15:13 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-18 15:18:51 +0000 (Tue, 18 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read /etc/default/useradd (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/useradd" );
	script_tag( name: "summary", value: "useradd command creates a new user account using the values
specified on the command line plus the default values from the system. Depending on command line
options, the useradd command will update system files and may also create the new user's home
directory and copy initial files.

The file /etc/default/useradd stores default values for account creation.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
file = "/etc/default/useradd";
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/" + file + "/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux/" + file + "/stat/ERROR", value: TRUE );
	exit( 0 );
}
policy_linux_stat_file( socket: sock, file: file );
policy_linux_file_content( socket: sock, file: file );
exit( 0 );

