if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11166" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "KF Web Server /%00 bug" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "upgrade to the latest version of KF Web Server" );
	script_tag( name: "summary", value: "Requesting a URL with '/%00' appended to it
  makes some versions of KF Web Server to dump the listing of the
  directory, thus showing potentially sensitive files." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buffer = http_get( item: "/%00", port: port );
data = http_keepalive_send_recv( port: port, data: buffer );
if(!data){
	exit( 0 );
}
if(egrep( string: data, pattern: ".*File Name.*Size.*Date.*Type.*" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

