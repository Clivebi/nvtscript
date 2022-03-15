if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150155" );
	script_version( "2020-03-11T14:35:36+0000" );
	script_tag( name: "last_modification", value: "2020-03-11 14:35:36 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 14:29:41 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read /etc/audit/audit.rules (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/7/audit.rules" );
	script_tag( name: "summary", value: "audit.rules is a file containing audit rules that will be
loaded by the audit daemons init script whenever the daemon is started. The auditctl program is used
by the initscripts to perform this operation. The syntax for the rules is essentially the same as
when typing in an auditctl command at a shell prompt except you do not need to type the auditctl
command name since that is implied. The audit rules come in 3 varieties: control, file, and syscall.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
file = "/etc/audit/audit.rules";
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/" + file + "/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux/" + file + "/stat/ERROR", value: TRUE );
	exit( 0 );
}
policy_linux_stat_file( socket: sock, file: file );
policy_linux_file_content( socket: sock, file: file );
exit( 0 );

