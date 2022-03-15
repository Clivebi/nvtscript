if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96007" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Find OS/2 and Posix Subsystem over WMI (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Find OS/2 and Posix Subsystem over WMI (win)" );
	exit( 0 );
}
require("wmi_file.inc.sc");
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
win_dir = get_kb_item( "WMI/WMI_OSWINDIR" );
win_dir = split( buffer: win_dir, sep: ":", keep: 0 );
win_dir = win_dir[0] + ":\\" + win_dir[1];
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/SessionManagerOS2", value: "error" );
	set_kb_item( name: "WMI/SessionManagerPosix", value: "error" );
	set_kb_item( name: "WMI/SessionManager/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
handlereg = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/SessionManagerOS2", value: "error" );
	set_kb_item( name: "WMI/SessionManagerPosix", value: "error" );
	set_kb_item( name: "WMI/SessionManager/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
if(OSVER != "5.2" || ContainsString( "Microsoft(R) Windows(R) XP Professional x64 Edition", OSNAME )){
	set_kb_item( name: "WMI/SessionManagerOS2", value: "error" );
	set_kb_item( name: "WMI/SessionManagerPosix", value: "error" );
	set_kb_item( name: "WMI/SessionManager/log", value: "The System is an " + OSNAME + " System" );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
if( !isnull( win_dir ) ){
	filespec1 = win_dir + "\\\\system32\\\\os2.exe";
	filespec2 = win_dir + "\\\\system32\\\\os2srv.exe";
	filespec3 = win_dir + "\\\\system32\\\\os2ss.exe";
	r1 = wmi_file_check_file_exists( handle: handle, filePath: filespec1 );
	r2 = wmi_file_check_file_exists( handle: handle, filePath: filespec2 );
	r3 = wmi_file_check_file_exists( handle: handle, filePath: filespec3 );
	if( r1 == "1" && r2 == "1" && r3 == "1" ){
		set_kb_item( name: "WMI/OS2", value: "on" );
	}
	else {
		set_kb_item( name: "WMI/OS2", value: "off" );
	}
}
else {
	log_message( port: 0, proto: "IT-Grundschutz", data: NASLString( "Error getting SMB-File.\\n" ) );
	set_kb_item( name: "WMI/OS2", value: "error" );
}
if( !isnull( win_dir ) ){
	filespec1 = win_dir + "\\\\system32\\\\psxdll.dll";
	filespec2 = win_dir + "\\\\system32\\\\pax.exe";
	filespec3 = win_dir + "\\\\system32\\\\posix.exe";
	filespec4 = win_dir + "\\\\system32\\\\psxss.exe";
	r1 = wmi_file_check_file_exists( handle: handle, filePath: filespec1 );
	r2 = wmi_file_check_file_exists( handle: handle, filePath: filespec2 );
	r3 = wmi_file_check_file_exists( handle: handle, filePath: filespec3 );
	r4 = wmi_file_check_file_exists( handle: handle, filePath: filespec4 );
	if( r1 == "1" && r2 == "1" && r3 == "1" && r4 == "1" ){
		set_kb_item( name: "WMI/Posix", value: "on" );
	}
	else {
		set_kb_item( name: "WMI/Posix", value: "off" );
	}
}
else {
	log_message( port: 0, proto: "IT-Grundschutz", data: NASLString( "Error getting SMB-File.\\n" ) );
	set_kb_item( name: "WMI/Posix", value: "error" );
}
keyexist = wmi_reg_enum_value( wmi_handle: handlereg, key: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems" );
if(!keyexist){
	log_message( port: 0, proto: "IT-Grundschutz", data: "Registry Path not found." );
	set_kb_item( name: "WMI/SessionManagerOS2", value: "error" );
	set_kb_item( name: "WMI/SessionManagerPosix", value: "error" );
	exit( 0 );
}
OS2 = wmi_reg_get_sz( wmi_handle: handlereg, key: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems", key_name: "Os2" );
posix = wmi_reg_get_sz( wmi_handle: handlereg, key: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems", key_name: "Posix" );
if( OS2 ){
	set_kb_item( name: "WMI/SessionManagerOS2", value: "on" );
}
else {
	set_kb_item( name: "WMI/SessionManagerOS2", value: "off" );
}
if( posix ){
	set_kb_item( name: "WMI/SessionManagerPosix", value: "on" );
}
else {
	set_kb_item( name: "WMI/SessionManagerPosix", value: "off" );
}
wmi_close( wmi_handle: handle );
wmi_close( wmi_handle: handlereg );
exit( 0 );

