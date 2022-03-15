if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10746" );
	script_version( "2021-08-09T14:28:51+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 14:28:51 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Compaq WBEM Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 2301 );
	script_mandatory_keys( "CompaqHTTPServer/banner" );
	script_tag( name: "solution", value: "Disable the Anonymous access to Compaq WBEM web server, or
  block the web server's port number on your Firewall." );
	script_tag( name: "summary", value: "We detected the remote web server to be a Compaq WBEM server.

  This web server enables attackers to gather sensitive information on the remote host, especially
  if anonymous access has been enabled." );
	script_tag( name: "insight", value: "Sensitive information includes: Platform name and version
  (including service packs), installed hotfixes, Running services, installed Drivers, boot.ini
  content, registry settings, NetBIOS name, system root directory, administrator full name, CPU
  type, CPU speed, ROM versions and revisions, memory size, sever recovery settings, and more." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 2301, ignore_broken: TRUE );
buf = http_get_remote_headers( port: port, ignore_broken: TRUE );
if(!buf){
	exit( 0 );
}
if(egrep( pattern: "^Server\\s*:\\s*CompaqHTTPServer/", string: buf, icase: TRUE )){
	set_kb_item( name: "compaq/http_server/detected", value: TRUE );
	set_kb_item( name: "compaq/http_server/http/detected", value: TRUE );
	mod_buf = strstr( buf, "Server: CompaqHTTPServer/" );
	mod_buf = mod_buf - "Server: CompaqHTTPServer/";
	subbuf = strstr( mod_buf, NASLString( "\\n" ) );
	mod_buf = mod_buf - subbuf;
	version = mod_buf;
	wbem_version = "false";
	if(ContainsString( buf, "var VersionCheck = " )){
		concl = buf;
		mod_buf = strstr( buf, "var VersionCheck = " );
		mod_buf = mod_buf - NASLString( "var VersionCheck = " );
		mod_buf = mod_buf - raw_string( 0x22 );
		subbuf = strstr( mod_buf, raw_string( 0x22 ) );
		mod_buf = mod_buf - subbuf;
		wbem_version = mod_buf;
	}
	buf = "Remote Compaq HTTP server version is: ";
	buf = buf + version;
	if(!( wbem_version == "false" )){
		buf = NASLString( buf, "\\nCompaq WBEM server version: " );
		buf = buf + wbem_version;
	}
	log_message( data: buf, port: port );
	register_and_report_cpe( app: "Compaq WEBM", ver: wbem_version, concluded: concl, base: "cpe:/a:hp:http_server:", expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

