if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150104" );
	script_version( "2020-07-29T07:27:10+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 07:27:10 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-28 09:58:33 +0100 (Tue, 28 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Hidden executables" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_gnu_bash_detect_lin.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linoxide.com/how-tos/stickbit-suid-guid/" );
	script_tag( name: "summary", value: "Malicious programs, code, and scripts usually start with a dot
(.) to hide themselves.

Note: This script dramatically increases the scan duration." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "find / -type f -executable";
title = "Hidden executables";
solution = "Inspect file and remove if necessary.";
test_type = "SSH_Cmd";
default = "None";
comment = "";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection";
}
else {
	if( !get_kb_item( "bash/linux/detected" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Bash is not available on the target host but needed for this test.";
	}
	else {
		compliant = "yes";
		ssh_cmd = "/bin/bash -c 'for f in $(find / -type f -executable -print 2>/dev/null); do if [[ $(basename $f) == .* ]]; then echo $f; fi; done'";
		files = ssh_cmd( cmd: ssh_cmd, socket: sock, nosh: TRUE );
		if(files){
			compliant = "no";
			files_list = split( buffer: files, keep: FALSE );
			for file in files_list {
				value += "," + file;
			}
		}
		if( value ) {
			value = str_replace( string: value, find: ",", replace: "", count: 1 );
		}
		else {
			value = "None";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

