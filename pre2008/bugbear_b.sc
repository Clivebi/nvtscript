if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11707" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Bugbear.B web backdoor" );
	script_category( ACT_GATHER_INFO );
	script_family( "Malware" );
	script_copyright( "Copyright (C) 2005 StrongHoldNet" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 81 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "ftp://ftp.f-secure.com/anti-virus/tools/f-bugbr.zip" );
	script_xref( name: "URL", value: "http://www.f-secure.com/v-descs/bugbear_b.shtml" );
	script_tag( name: "solution", value: "Use your favorite antivirus to disinfect your
  system. Standalone disinfection tools also exist and is linked in the references." );
	script_tag( name: "summary", value: "Your system seems to be infected by the Bugbear.B virus
  (its backdoor has been detected on port 81)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 81 );
url = NASLString( "/%NETHOOD%/" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req );
if(!buf){
	exit( 0 );
}
if(ereg( pattern: "^HTTP/[0-9]\\.[0-9] 200 ", string: buf ) && ContainsString( buf, "Microsoft Windows Network" )){
	security_message( port: port );
}

