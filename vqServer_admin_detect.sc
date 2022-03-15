if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10354" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "vqServer administrative port" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Service detection" );
	script_dependencies( "gb_vqserver_detect.sc" );
	script_mandatory_keys( "vqserver/detected" );
	script_tag( name: "summary", value: "vqSoft's vqServer administrative port is open." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 9090, proto: "vqServer-admin" );
banner = http_get_cache( item: "/", port: port );
if(ContainsString( banner, "Server: vqServer" ) && ContainsString( banner, "WWW-Authenticate: Basic realm=/" )){
	res = strstr( banner, "Server: " );
	sub = strstr( res, NASLString( "\\n" ) );
	res = res - sub;
	res = res - "Server: ";
	res = res - "\\n";
	banner = NASLString( "vqServer version is : " );
	banner = banner + res;
	log_message( port: port, data: banner );
}
exit( 0 );

