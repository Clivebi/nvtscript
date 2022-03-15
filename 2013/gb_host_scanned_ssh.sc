if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103625" );
	script_version( "2021-03-23T06:51:29+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "creation_date", value: "2012-12-14 10:37:58 +0100 (Fri, 14 Dec 2012)" );
	script_name( "Leave information on scanned hosts" );
	script_category( ACT_END );
	script_family( "General" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "host_scan_end.sc", "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_add_preference( name: "Enable", type: "checkbox", value: "no", id: 1 );
	script_add_preference( name: "Use File", type: "checkbox", value: "no", id: 2 );
	script_add_preference( name: "File name /tmp/", type: "entry", value: "scan_info.txt", id: 3 );
	script_add_preference( name: "Append to File", type: "checkbox", value: "no", id: 4 );
	script_add_preference( name: "Use Syslog", type: "checkbox", value: "no", id: 5 );
	script_add_preference( name: "Syslog priority", type: "radio", value: "info;debug;notice;warning;err;crit;alert;emerg", id: 6 );
	script_add_preference( name: "Syslog tag", type: "entry", value: "VulScan", id: 7 );
	script_add_preference( name: "Message", type: "entry", value: "Security Scan of ::HOSTNAME:: finished. Start: ::SCAN_START:: Stop: ::SCAN_STOP::", id: 8 );
	script_tag( name: "summary", value: "This routine stores information about the scan on the scanned host,
  provided it is a unixoid system offering ssh access with a standard shell.

  The information cover hostname, scan start time and scan end time.
  No details about the actual scan results are stored on the scanned host.

  By default, this routine is disabled even it is selected to run. To activate
  it, it needs to be explicitly enabled with its corresponding preference switch.

  The preference 'Message' may contain 3 placeholder where respective content
  will be inserted into the message when the message is finally created on the
  target system:

  '::HOSTNAME::', '::SCAN_START::' and '::SCAN_STOP::'.

  Two methods are offered (one or even both concurrently can be used):

  * Syslog: The utility 'logger' on the target system is used to issue the
  message. The message will appear in the standard log environment as configured
  on the corresponding target system. Error is reported in case the logger
  utility is not available.

  * File: A filename under /tmp can be chosen where the message is left. It is
  configurable to either overwrite the file each time or to append new
  information. A token is added to this file to ensure only files created by
  this routine are used. Error is reported when the access rights are not
  sufficient or symbolic links detected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ssh_func.inc.sc");
enabled = script_get_preference( name: "Enable", id: 1 );
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
file_security_token = "b3BlbnZhcy1zY2FubmVyLXRydXN0Cg";
func get_disallowed_signs(  ){
	return make_list( "\0",
		 "'" );
}
func get_disallowed_str(  ){
	disallowed = get_disallowed_signs();
	ua_str = "";
	for ua in disallowed {
		ua_str += ua + " ";
	}
	return ua_str;
}
func check_file( file ){
	disallowed = get_disallowed_signs();
	disallowed = make_list( "..",
		 "/",
		 disallowed );
	for ua in disallowed {
		if(ContainsString( file, ua )){
			return FALSE;
		}
	}
	return TRUE;
}
func check_message( message ){
	disallowed = get_disallowed_signs();
	for ua in disallowed {
		if(ContainsString( message, ua )){
			return FALSE;
		}
	}
	return TRUE;
}
func fancy_date( datestr ){
	if(int( datestr ) < 10){
		return NASLString( "0", datestr );
	}
	return datestr;
}
func make_date_str( date ){
	time = localtime( date );
	month = fancy_date( time["mon"] );
	day = fancy_date( time["mday"] );
	hour = fancy_date( time["hour"] );
	minute = fancy_date( time["min"] );
	sec = fancy_date( time["sec"] );
	return time["year"] + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + sec;
}
func replace_placeholders( message ){
	var message;
	if(ContainsString( message, "::HOSTNAME::" )){
		message = str_replace( string: message, find: "::HOSTNAME::", replace: get_host_name() );
	}
	if(ContainsString( message, "::SCAN_START::" )){
		start = get_kb_item( "/tmp/start_time" );
		if( start ){
			scan_start = make_date_str( date: start );
		}
		else {
			scan_start = "Scan start unknown (host_alive_detection.nasl not launched?)";
		}
		message = str_replace( string: message, find: "::SCAN_START::", replace: scan_start );
	}
	if(ContainsString( message, "::SCAN_STOP::" )){
		stop = get_kb_item( "/tmp/stop_time" );
		if( stop ){
			scan_stop = make_date_str( date: stop );
		}
		else {
			scan_stop = make_date_str( date: unixtime() );
		}
		message = str_replace( string: message, find: "::SCAN_STOP::", replace: scan_stop );
	}
	return message;
}
message = script_get_preference( name: "Message", id: 8 );
if(strlen( message ) < 1){
	log_message( port: 0, data: "No Message was given. Can not execute this test without a message." );
	ssh_close_connection();
	exit( 1 );
}
if(!check_message( message: message )){
	log_message( port: 0, data: "Forbidden sign in 'message'. The following signs are not allowed: " + get_disallowed_str() );
	ssh_close_connection();
	exit( 1 );
}
message = replace_placeholders( message: message );
syslog = script_get_preference( name: "Use Syslog", id: 5 );
if(ContainsString( syslog, "yes" )){
	syslog_tag = script_get_preference( name: "Syslog tag", id: 7 );
	syslog_priority = script_get_preference( name: "Syslog priority", id: 6 );
	if(syslog_tag){
		if(!check_message( message: syslog_tag )){
			log_message( port: 0, data: "Forbidden sign in Syslog tag '" + syslog_tag + "'. The following signs are not allowed: " + get_disallowed_str() );
			ssh_close_connection();
			exit( 1 );
		}
	}
	check4logger = ssh_cmd( socket: soc, cmd: "logger --help" );
	if(ContainsString( check4logger, "not found" )){
		log_message( port: 0, data: "You have enabled syslog but It seems that the 'logger' command is not" + "\n" + "available on the remote host." + "\n" + "The 'logger' utility is part of the bsdutils package on Debian-based" + "\n" + "systems and the util-linux-ng package on Fedora." );
		ssh_close_connection();
		exit( 1 );
	}
	cmd = "logger ";
	if(syslog_tag){
		cmd += "-t '" + syslog_tag + "' ";
	}
	if(syslog_priority){
		cmd += "-p '" + syslog_priority + "' ";
	}
	cmd += "-- '" + message + "'; echo $?";
	send_message = ssh_cmd( socket: soc, cmd: cmd );
	send_message_int = int( send_message );
	if( send_message_int > 0 ){
		log_message( port: 0, data: "Sending message to syslog failed. Error: " + chomp( send_message ) );
	}
	else {
		log_message( port: 0, data: "Message '" + message + "' successfully send to syslog." );
	}
}
filelog = script_get_preference( name: "Use File", id: 2 );
if(ContainsString( filelog, "yes" )){
	path = script_get_preference( name: "File name /tmp/", id: 3 );
	append = script_get_preference( name: "Append to File", id: 4 );
	path = chomp( path );
	if(!check_file( file: path )){
		log_message( port: 0, data: "Forbidden sign in filename '" + path + "'. The following signs are not allowed: " + get_disallowed_str() + " .. /" );
		ssh_close_connection();
		exit( 1 );
	}
	dir_exist = ssh_cmd( socket: soc, cmd: "ls -d '/tmp'" );
	if(ContainsString( tolower( dir_exist ), "no such file" )){
		log_message( port: 0, data: "It seems that /tmp does not exist. Can't create file /tmp/" + path );
		ssh_close_connection();
		exit( 1 );
	}
	path = "/tmp/" + path;
	file_exist = ssh_cmd( socket: soc, cmd: "ls -l '" + path + "'" );
	if(IsMatchRegexp( file_exist, "^l[^s]" )){
		log_message( port: 0, data: "File '" + path + "' is a symbolic link and this is not allowed. Can not continue." );
		ssh_close_connection();
		exit( 1 );
	}
	if(!ContainsString( tolower( file_exist ), "no such file" )){
		current_content = ssh_cmd( socket: soc, cmd: "cat '" + path + "'" );
		if(strlen( current_content ) > 0){
			if(!ContainsString( current_content, file_security_token )){
				log_message( port: 0, data: "Security Token '" + file_security_token + "' not found in existing file '" + path + "'. Can not continue." );
				ssh_close_connection();
				exit( 1 );
			}
			if(ContainsString( append, "yes" )){
				file_security_token = NULL;
			}
		}
	}
	redirect = ">";
	if(ContainsString( append, "yes" )){
		redirect += ">";
	}
	cmd = "echo '";
	if(file_security_token){
		cmd += "<token>" + file_security_token + "</token>\n";
	}
	cmd += message + "' " + redirect + " '" + path + "'";
	cmd += " ; echo $?";
	ssh_cmd( socket: soc, cmd: cmd );
	new_content = ssh_cmd( socket: soc, cmd: "cat '" + path + "'" );
	if( !ContainsString( new_content, message ) ){
		log_message( port: 0, data: "Sending message to '" + path + "' failed." );
		ssh_close_connection();
		exit( 1 );
	}
	else {
		log_message( port: 0, data: "Message '" + message + "' successfully send to '" + path + "'." );
		ssh_close_connection();
		exit( 0 );
	}
}
ssh_close_connection();
exit( 0 );

