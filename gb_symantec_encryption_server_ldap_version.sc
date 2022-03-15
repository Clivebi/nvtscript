if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105559" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-24 13:49:24 +0100 (Wed, 24 Feb 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Symantec Encryption Server Detection (LDAP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "ldap_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "ldap/detected" );
	script_tag( name: "summary", value: "This script performs LDAP based detection of Symantec Encryption Server" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("ldap.inc.sc");
port = ldap_get_port( default: 389 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x30, 0x4e, 0x02, 0x01, 0x02, 0x63, 0x49, 0x04, 0x10, 0x63, 0x6e, 0x3d, 0x70, 0x67, 0x70, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x0a, 0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x19, 0x04, 0x0b, 0x70, 0x67, 0x70, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x04, 0x0a, 0x70, 0x67, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e );
send( socket: soc, data: req );
recv = recv( socket: soc, length: 512 );
close( soc );
if(!ContainsString( recv, "pgpVersion" ) || !ContainsString( recv, "PGPServerInfo" ) || !ContainsString( recv, "PGP Universal Server" )){
	exit( 0 );
}
set_kb_item( name: "symantec_encryption_server/installed", value: TRUE );
cpe = "cpe:/a:symantec:encryption_management_server";
resp = bin2string( ddata: recv, noprint_replacement: " " );
version = eregmatch( pattern: "pgpVersion[^ ]*[ ]+([0-9.]+) \\(", string: resp );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "symantec_encryption_server/ldap/version", value: vers );
	cpe += ":" + vers;
}
_build = eregmatch( pattern: "pgpVersion[^ ]*[ ]+[0-9.]+ \\(Build ([0-9]+)\\)", string: resp );
if(!isnull( _build[1] )){
	build = _build[1];
	set_kb_item( name: "symantec_encryption_server/ldap/build", value: build );
}
report = "Detected Symantec Encryption Server\n";
if(vers){
	report += "Version: " + vers + "\n";
}
if(build){
	report += "Build  : " + build + "\n";
}
report += "CPE: " + cpe + "\n";
log_message( port: port, data: report );
exit( 0 );

