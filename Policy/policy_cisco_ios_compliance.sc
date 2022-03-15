if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106431" );
	script_version( "$Revision: 11659 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-27 17:16:14 +0200 (Thu, 27 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "98" );
	script_name( "Cisco IOS Compliance Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_cisco_ios_version_ssh.sc" );
	script_mandatory_keys( "cisco_ios/detected" );
	script_tag( name: "summary", value: "Runs the Cisco IOS Compliance Check with the provided policy file and
  stores the results in the kb." );
	script_add_preference( name: "Cisco IOS Policies", type: "file", value: "" );
	script_add_preference( name: "Enable Password", type: "password", value: "" );
	exit( 0 );
}
require("ssh_func.inc.sc");
if(!get_kb_item( "cisco_ios/detected" )){
	exit( 0 );
}
func check_rule( config, pattern, section, present ){
	if(section){
		ok = FALSE;
		for(i = 0;i < max_index( config );i++){
			sec = eregmatch( pattern: section, string: config[i] );
			if(!isnull( sec )){
				j = 1;
				sec_ok = FALSE;
				for(;ereg( pattern: "^ ", string: config[i + j] );){
					match = eregmatch( pattern: pattern, string: config[i + j] );
					if(( !isnull( match ) && present == "true" ) || ( isnull( match ) && present == "false" )){
						sec_ok = TRUE;
					}
					j++;
				}
				if( sec_ok ) {
					ok = TRUE;
				}
				else {
					ok = FALSE;
				}
				i = i + j - 1;
			}
		}
		return ok;
	}
	for line in config {
		match = eregmatch( pattern: pattern, string: line );
		if(( !isnull( match ) && present == "true" ) || ( isnull( match ) && present == "false" )){
			return TRUE;
		}
	}
	return FALSE;
}
policy_file = script_get_preference_file_content( "Cisco IOS Policies" );
if(!policy_file){
	exit( 0 );
}
policy_lines = split( buffer: policy_file, keep: FALSE );
max = max_index( policy_lines );
if(max < 5){
	set_kb_item( name: "policy/cisco_ios_compliance/error", value: "The Cisco IOS policy is empty. No check can be done.\\n" );
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
enable_password = script_get_preference( "Enable Password" );
if( !isnull( enable_password ) ){
	sess = ssh_session_id_from_sock( sock );
	if(!sess){
		close( sock );
		exit( 0 );
	}
	shell = ssh_shell_open( sess );
	if(!shell){
		close( sock );
		exit( 0 );
	}
	ssh_shell_write( session: shell, cmd: "enable\n" );
	buf = ssh_read_from_shell( sess: shell, pattern: "Password:" );
	if(!buf || !ContainsString( buf, "Password:" )){
		close( sock );
		exit( 0 );
	}
	ssh_shell_write( session: shell, cmd: enable_password + "\n" );
	buf = ssh_read_from_shell( sess: shell, pattern: "#" );
	if(!buf || !ContainsString( buf, "#" )){
		close( sock );
		exit( 0 );
	}
	ssh_shell_write( session: shell, cmd: "terminal length 0\n" );
	ssh_shell_write( session: shell, cmd: "show running-config\n" );
	config = ssh_read_from_shell( sess: shell, pattern: "^end$", timeout: 30, retry: 10 );
}
else {
	config = ssh_cmd( socket: sock, cmd: "show running-config\n", nosh: TRUE );
}
if(sock){
	close( sock );
}
config = ereg_replace( pattern: "!..", string: config, replace: "" );
config = split( buffer: config, keep: FALSE );
if(max_index( config ) < 5){
	set_kb_item( name: "policy/cisco_ios_compliance/error", value: "The retrieved IOS configuration seems to be to small (< 5 lines). Check if the login
account has enough privilege to run 'show running-config'. No checks will be done.\\n" );
	exit( 0 );
}
for(r = 0;r < max;r++){
	if(policy_lines[r] == ""){
		continue;
	}
	entry = split( buffer: policy_lines[r], sep: ":", keep: FALSE );
	if( entry[0] == "title" ) {
		title = entry[1];
	}
	else {
		if( entry[0] == "desc" ) {
			desc = entry[1];
		}
		else {
			if( entry[0] == "solution" ) {
				solution = entry[1];
			}
			else {
				if( entry[0] == "fix" ) {
					fix = entry[1];
				}
				else {
					if( entry[0] == "section" ) {
						section = entry[1];
					}
					else {
						if( entry[0] == "pattern" ) {
							pattern = entry[1];
						}
						else {
							if(entry[0] == "present"){
								present = entry[1];
							}
						}
					}
				}
			}
		}
	}
	if(( r == max - 1 ) || ( policy_lines[r + 1] == "" )){
		if( check_rule( config: config, section: section, pattern: pattern, present: present ) ) {
			comp_pass += title + "||" + desc + "||" + pattern + "||" + present + "\n";
		}
		else {
			comp_fail += title + "||" + desc + "||" + solution;
			if(fix && fix != ""){
				comp_fail += "||" + fix;
			}
			comp_fail += "\n";
		}
		section = "";
		fix = "";
	}
}
if(comp_pass){
	set_kb_item( name: "policy/cisco_ios_compliance/passed", value: comp_pass );
}
if(comp_fail){
	set_kb_item( name: "policy/cisco_ios_compliance/failed", value: comp_fail );
}
exit( 0 );

