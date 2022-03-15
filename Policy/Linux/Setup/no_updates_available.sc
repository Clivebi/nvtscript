if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109750" );
	script_version( "2021-03-03T15:26:07+0000" );
	script_tag( name: "last_modification", value: "2021-03-03 15:26:07 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "creation_date", value: "2019-01-18 09:31:06 +0100 (Fri, 18 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Package updates available" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.8 Ensure updates patches and additional security software are installed (Not Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 3.5 Deploy Automated Software Patch Management Tools" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 3.4 Deploy Automated Operating System Patch Management Tools" );
	script_tag( name: "summary", value: "Package updates may include vulnerability fixes or new
functionality to a package. Keeping the packages to the newest available version reduces the risk of
a successful attack." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "yum check-update,apt-get -s upgrade,zypper list-updates";
title = "Package updates available";
solution = "Update the system";
test_type = "SSH_Cmd";
default = "no";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "Error";
	comment = "No SSH connection to host";
}
else {
	update_cmds = policy_build_list_from_string( str: cmd );
	for update_cmd in update_cmds {
		cmd_no_errors = update_cmd + " 2>/dev/null";
		updates = ssh_cmd( socket: sock, cmd: cmd_no_errors );
		if(updates){
			if( ContainsString( cmd, "yum" ) ){
				value_split = split( buffer: updates, keep: FALSE );
				if( max_index( value_split ) > 1 ){
					value = "yes";
				}
				else {
					value = "no";
				}
			}
			else {
				if( ContainsString( cmd, "apt-get" ) ){
					if( IsMatchRegexp( updates, "0\\s+upgraded" ) ){
						value = "no";
					}
					else {
						value = "yes";
					}
				}
				else {
					if(ContainsString( cmd, "zypper" )){
						if( IsMatchRegexp( updates, "no\\s+updates\\s+found" ) ){
							value = "no";
						}
						else {
							value = "yes";
						}
					}
				}
			}
			break;
		}
	}
	if( !value ){
		compliant = "incomplete";
		value = "Error";
		comment = "Host did not recognize yum, apt-get or zypper";
	}
	else {
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

