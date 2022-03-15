if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14269" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10891 );
	script_xref( name: "OSVDB", value: "8657" );
	script_xref( name: "OSVDB", value: "8658" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "YaPiG Remote Server-Side Script Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to YaPiG 0.92.2 or later." );
	script_tag( name: "summary", value: "The remote version of YaPiG may allow a remote attacker to execute
  malicious scripts on a vulnerable system." );
	script_tag( name: "insight", value: "This issue exists due to a lack of sanitization of user-supplied data.
  It is reported that an attacker may be able to upload content that will be saved on the server with a '.php'
  extension.  When this file is requested by the attacker, the contents of the file will be parsed and executed by the
  PHP engine, rather than being sent." );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow an attacker to execute malicious
  script code on a vulnerable server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0756.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/yapig", "/gallery", "/photos", "/photo", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/" ), port: port );
	if(!res){
		continue;
	}
	if(egrep( pattern: "Powered by .*YaPig.* V0\\.([0-8][0-9][^0-9]|9([01]|2[ab]))", string: res )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

