if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96171" );
	script_version( "2021-03-23T06:51:29+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-03-03 10:37:58 +0100 (Sun, 03 Mar 2013)" );
	script_name( "Leave information on scanned Windows hosts" );
	script_category( ACT_END );
	script_family( "Windows" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_wmi_access.sc", "host_scan_end.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_add_preference( name: "Enable", type: "checkbox", value: "no", id: 1 );
	script_add_preference( name: "Message", type: "entry", value: "Security Scan of ::HOSTNAME:: finished. Start: ::SCAN_START:: Stop: ::SCAN_STOP::", id: 2 );
	script_tag( name: "summary", value: "This routine stores information about the scan on the scanned host,
  provided it is a Windows system remote registry and wmi access.

  The information cover hostname, scan start time and scan end time.
  No details about the actual scan results are stored on the scanned host.

  By default, this routine is disabled even it is selected to run. To activate
  it, it needs to be explicitly enabled with its corresponding preference switch.

  The preference 'Message' may contain 3 placeholder where respective content
  will be inserted into the message when the message is finally created on the
  target system:

  '::HOSTNAME::', '::SCAN_START::' and '::SCAN_STOP::'.

  At the end of the scan, the message will be written into the registry
  key 'SOFTWARE\\VulScanInfo'." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("wmi_os.inc.sc");
require("smb_nt.inc.sc");
enabled = script_get_preference( name: "Enable", id: 1 );
if(!ContainsString( enabled, "yes" )){
	exit( 0 );
}
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handlereg = wmi_connect_reg( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handlereg){
	exit( 0 );
}
key = "SOFTWARE\\VulScanInfo";
ex_str = "Scanstate";
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
message = script_get_preference( name: "Message", id: 2 );
if(strlen( message ) < 1){
	wmi_close( wmi_handle: handlereg );
	log_message( port: 0, data: "No Message was given. Can not execute this test without a message." );
	exit( 0 );
}
message = replace_placeholders( message: message );
checkkey = wmi_reg_create_key( wmi_handle: handlereg, key: key );
if(!checkkey){
	wmi_close( wmi_handle: handlereg );
	log_message( port: 0, data: "Error, can't set the Registry Key." );
	exit( 0 );
}
checkstring = wmi_reg_set_ex_string_val( wmi_handle: handlereg, key: key, val_name: ex_str, val: message );
if(!checkstring){
	wmi_close( wmi_handle: handlereg );
	log_message( port: 0, data: "Error, can't set the Registry String" );
	exit( 0 );
}
wmi_close( wmi_handle: handlereg );
log_message( port: 0, data: "Registry Key '" + key + "' with Message '" + message + "' successfully created." );
exit( 0 );

