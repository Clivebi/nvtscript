if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11071" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2975 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-1248" );
	script_name( "ASP source using %20 trick" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Install all the latest security patches." );
	script_tag( name: "summary", value: "It is possible to get the source code of the remote
  ASP scripts by appending %20 at the end of the request (like GET /default.asp%20)

  ASP source code usually contains sensitive information such as logins and passwords." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
func check( file, port ){
	var file, port;
	var url, req, res;
	url = NASLString( file, "%20" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !ereg( pattern: "^HTTP/1\\.[01] 200", string: res )){
		return FALSE;
	}
	if(ContainsString( res, "Content-Type: application/octet-stream" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		return TRUE;
	}
	if(( ContainsString( res, "<%" ) ) && ( ContainsString( res, "%>" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		return TRUE;
	}
	return FALSE;
}
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
if(check( file: "/default.asp", port: port )){
	exit( 0 );
}
files = http_get_kb_file_extensions( port: port, host: host, ext: "asp" );
if(!files){
	exit( 0 );
}
files = make_list( files );
check( file: files[0], port: port );

