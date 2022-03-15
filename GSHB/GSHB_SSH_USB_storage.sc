if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96086" );
	script_version( "2021-06-11T09:28:25+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 09:28:25 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-05-10 16:35:52 +0200 (Mon, 10 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Find and list USB-Storage Modules, list plugged USB-Storage Devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to find and list USB-Storage Modules, list plugged USB-Storage Devices." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = get_preference( "auth_port_ssh" );
if(!port){
	port = ssh_get_port( default: 22, ignore_unscanned: TRUE );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	log_message( port: port, data: error );
	set_kb_item( name: "GSHB/usbmodules", value: "error" );
	set_kb_item( name: "GSHB/usbstorage", value: "error" );
	set_kb_item( name: "GSHB/usbbus", value: "error" );
	set_kb_item( name: "GSHB/usbmodules/log", value: error );
	exit( 0 );
}
uname = get_kb_item( "ssh/login/uname" );
if( !IsMatchRegexp( uname, "SunOS .*" ) ){
	usbmodules = ssh_cmd( socket: sock, cmd: "find /lib/modules/ | grep -i usb-storage.ko" );
	usbstorage = ssh_cmd( socket: sock, cmd: "cat /sys/kernel/debug/usb/devices | grep -i -A2 -B5 usb-storage" );
	usbbus = ssh_cmd( socket: sock, cmd: "find /sys/bus/ | grep -i usb-storage" );
}
else {
	if(IsMatchRegexp( uname, "SunOS .*" )){
		usbmodules = ssh_cmd( socket: sock, cmd: "/usr/sbin/modinfo|grep -i usb" );
		usbstorage = ssh_cmd( socket: sock, cmd: "rmformat -l" );
		if(!IsMatchRegexp( usbstorage, ".*Bus: USB.*" )){
			usbstorage = "none";
		}
		usbbus = "none";
	}
}
if(ContainsString( usbmodules, "FIND: Invalid switch" ) || ContainsString( usbmodules, "FIND: Parameterformat falsch" )){
	set_kb_item( name: "GSHB/usbbus", value: "windows" );
	set_kb_item( name: "GSHB/usbmodules", value: "windows" );
	set_kb_item( name: "GSHB/usbstorage", value: "windows" );
	exit( 0 );
}
if(IsMatchRegexp( usbstorage, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( usbstorage, ".*No such file or directory.*" ) || IsMatchRegexp( usbstorage, "cat: .* /sys/kernel/debug/usb/devices:.*" )){
	usbstorage = "none";
}
if(IsMatchRegexp( usbmodules, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( usbmodules, ".*No such file or directory.*" )){
	usbmodules = "none";
}
if(IsMatchRegexp( usbbus, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( usbbus, ".*No such file or directory.*" )){
	usbbus = "none";
}
if(!usbmodules){
	usbmodules = "none";
}
if(!usbstorage){
	usbstorage = "none";
}
if(!usbbus){
	usbbus = "none";
}
set_kb_item( name: "GSHB/usbbus", value: usbbus );
set_kb_item( name: "GSHB/usbmodules", value: usbmodules );
set_kb_item( name: "GSHB/usbstorage", value: usbstorage );
exit( 0 );

