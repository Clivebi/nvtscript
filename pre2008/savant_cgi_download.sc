if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10623" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1313 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2000-0521" );
	script_name( "Savant original form CGI access" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_dependencies( "gb_savant_webserver_detect.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "savant/webserver/detected" );
	script_xref( name: "URL", value: "http://www.securiteam.com/exploits/Savant_Webserver_exposes_CGI_script_source.html" );
	script_tag( name: "summary", value: "A security vulnerability in the Savant web server allows attackers to download the original form of CGIs(unprocessed).
  This would allow them to see any sensitive information stored inside those CGIs." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Savant/" )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	if(http_is_cgi_installed_ka( port: port, item: NASLString( dir, "/cgitest.exe" ) )){
		data = http_get( item: NASLString( dir, "/cgitest.exe" ), port: port );
		soc = http_open_socket( port );
		send( socket: soc, data: data );
		res = http_recv( socket: soc );
		http_close_socket( soc );
		if( ( res[0] == NASLString( "M" ) ) && ( res[1] == NASLString( "Z" ) ) ){
			security_message( port: port );
			exit( 0 );
		}
		else {
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

