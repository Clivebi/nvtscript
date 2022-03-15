if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150552" );
	script_version( "2021-01-13T14:34:11+0000" );
	script_tag( name: "last_modification", value: "2021-01-13 14:34:11 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-13 13:36:01 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Get journald.conf (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.man7.org/linux/man-pages/man5/journald.conf.5.html" );
	script_tag( name: "summary", value: "The file configures various parameters of the systemd journal
service.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
file = "/etc/systemd/journald.conf";
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/" + file + "/ssh/ERROR", value: TRUE );
	exit( 0 );
}
cmd = "cat " + file;
ret = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE );
if(ret){
	set_kb_item( name: "Policy/linux/" + file + "/content", value: ret );
}
exit( 0 );

