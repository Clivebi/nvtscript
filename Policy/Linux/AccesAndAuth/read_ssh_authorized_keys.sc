if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150503" );
	script_version( "2020-12-21T11:14:51+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 11:14:51 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-21 10:53:12 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read ssh authorized_keys file" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.ssh.com/ssh/authorized_keys/" );
	script_tag( name: "summary", value: "The authorized_keys file in SSH specifies the SSH keys that can
be used for logging into the user account for which the file is configured. It is a highly important
configuration file, as it configures permanent access using SSH keys and needs proper management.

Note: This script outputs the content of the file ~/.ssh/authorized_keys only." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "cat ~/.ssh/authorized_keys";
title = "SSH Authorized Keys";
solution = "Edit ~/.ssh/authorized_keys";
test_type = "SSH_Cmd";
default = "N/A";
compliant = "incomplete";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	value = "Error";
	comment = "No SSH connection to host";
}
else {
	if(!value = ssh_cmd( cmd: cmd, socket: sock, return_errors: FALSE )){
		value = "Error";
		comment = "Could not read ~/.ssh/authorized_keys";
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

