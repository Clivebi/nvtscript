if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108157" );
	script_version( "2020-03-05T09:07:58+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-05 09:07:58 +0000 (Thu, 05 Mar 2020)" );
	script_tag( name: "creation_date", value: "2017-05-10 09:37:58 +0200 (Wed, 10 May 2017)" );
	script_name( "Leave Host Identification Tag on scanned host (SSH)" );
	script_category( ACT_END );
	script_family( "General" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_add_preference( name: "Enable", type: "checkbox", value: "no" );
	script_tag( name: "summary", value: "This routine leaves a host identification tag
  on a target host for later identification via the Asset Management, provided it
  is a unixoid system offering ssh access with a standard shell.

  The information covers an unique tag created for this specific host. No details
  about the actual scan results are stored on the scanned host.

  By default, this routine is disabled even it is selected to run. To activate
  it, it needs to be explicitly enabled with its corresponding preference switch.

  The file is named gvm_host_id_tag.txt and placed within the home directory (~/) of
  the user which was used to scan the target system." );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Leave Host Identification Tag on scanned host (SSH)";
enabled = script_get_preference( "Enable" );
if(!ContainsString( enabled, "yes" )){
	exit( 0 );
}
if(get_kb_item( "ssh/no_linux_shell" )){
	log_message( port: 0, data: "Target system does not offer a standard shell. Can not continue." );
	exit( 0 );
}
soc = ssh_login_or_reuse_connection();
if(!soc){
	exit( 0 );
}
file_security_token = "I75k48ddvdbwxLfgZH5DASxpoEVDzV8v";
file = "gvm_host_id_tag.txt";
path = "~/";
path_file = path + file;
dir_exist = ssh_cmd( socket: soc, cmd: "ls -d " + path );
if(ContainsString( tolower( dir_exist ), "no such file" )){
	log_message( port: 0, data: "Directory '" + path + "' does not exist. Can not create file '" + path_file + "' and continue." );
	ssh_close_connection();
	exit( 0 );
}
file_exist = ssh_cmd( socket: soc, cmd: "ls -l " + path_file );
if(IsMatchRegexp( file_exist, "^l[^s]" )){
	log_message( port: 0, data: "File '" + path_file + "' is a symbolic link and this is not allowed. Can not continue." );
	ssh_close_connection();
	exit( 0 );
}
if(ContainsString( tolower( file_exist ), "permission denied" )){
	log_message( port: 0, data: "Permission denied while accessing file '" + path_file + "'. Can not continue." );
	ssh_close_connection();
	exit( 0 );
}
if( !ContainsString( tolower( file_exist ), "no such file" ) ){
	current_content = ssh_cmd( socket: soc, cmd: "cat " + path_file );
	if( strlen( current_content ) > 0 ){
		if( !ContainsString( current_content, file_security_token ) ){
			log_message( port: 0, data: "Security Token '" + file_security_token + "' not found in existing file '" + path_file + "'. Can not continue." );
			ssh_close_connection();
			exit( 0 );
		}
		else {
			host_id = eregmatch( pattern: "<host_id>(.*)</host_id>", string: current_content );
			if( host_id[1] ){
				register_host_detail( name: "Host-ID-Tag", value: host_id[1], desc: SCRIPT_DESC );
				log_message( port: 0, data: "Host id tag '" + host_id[1] + "' successfully collected from '" + path_file + "'." );
			}
			else {
				log_message( port: 0, data: "Failed to collect host id tag from '" + path_file + "'. Possible malformed/invalid file." );
			}
		}
	}
	else {
		log_message( port: 0, data: "Empty response received while trying to collect host id tag from '" + path_file + "'." );
	}
}
else {
	rand = rand_str( length: 32 );
	cmd = "echo '";
	cmd += "<token>" + file_security_token + "</token>\n";
	cmd += "<host_id>" + rand + "</host_id>'";
	cmd += ">" + path_file + " ; echo $?";
	create_request = ssh_cmd( socket: soc, cmd: cmd );
	new_content = ssh_cmd( socket: soc, cmd: "cat " + path_file );
	if( !ContainsString( new_content, "<token>" ) && !ContainsString( new_content, "<host_id>" ) ){
		log_message( port: 0, data: "Sending host id tag to '" + path_file + "' failed. Response: " + create_request );
	}
	else {
		register_host_detail( name: "Host-ID-Tag", value: rand, desc: SCRIPT_DESC );
		log_message( port: 0, data: "Host id tag '" + rand + "' successfully send to '" + path_file + "'." );
	}
}
ssh_close_connection();
exit( 0 );

