if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105266" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-05-08 14:52:31 +0200 (Fri, 08 May 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Juniper ScreenOS Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ScreenOS/detected" );
	script_tag( name: "summary", value: "This script performs SSH based detection of Juniper ScreenOS" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "ScreenOS/detected" )){
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
system = ssh_cmd( socket: sock, cmd: "get system", nosh: TRUE, pty: TRUE, pattern: "Software Version: " );
if(!ContainsString( system, "Product Name:" ) || !ContainsString( system, "FPGA checksum" ) || !ContainsString( system, "Compiled by build_master at" ) || !ContainsString( system, "File Name:" )){
	exit( 0 );
}
set_kb_item( name: "ScreenOS/system", value: system );
vers = "unknown";
cpe = "cpe:/o:juniper:screenos";
version = eregmatch( pattern: "Software Version: ([^,]+)", string: system );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "ScreenOS/version", value: vers );
	cpe += ":" + vers;
}
type = eregmatch( pattern: "Software Version: [^,]+, Type: ([^\r\n]+)", string: system );
if(!isnull( type[1] )){
	t = type[1];
	set_kb_item( name: "ScreenOS/type", value: t );
}
register_product( cpe: cpe, location: "ssh" );
os_register_and_report( os: "Juniper ScreenOS", cpe: cpe, banner_type: "SSH login", desc: "Juniper ScreenOS Detection", runs_key: "unixoide" );
report = "Detected Juniper ScreenOS (ssh)\n\n" + "Version: " + vers + "\n";
if(type){
	report += "Type:    " + t + "\n";
}
report += "CPE:     " + cpe;
log_message( port: 0, data: report );
exit( 0 );

