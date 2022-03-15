if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10715" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2527 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "BEA WebLogic Scripts Server scripts Source Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 INTRANODE" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.bea.com" );
	script_tag( name: "solution", value: "Use the official patch available at the linked reference." );
	script_tag( name: "summary", value: "BEA WebLogic may be tricked into revealing the source code of JSP scripts
  by using simple URL encoding of characters in the filename extension.

  e.g.: default.js%70 (=default.jsp) won't be considered as a script but
  rather as a simple document." );
	script_tag( name: "affected", value: "Vulnerable systems: WebLogic version 5.1.0 SP 6

  Immune systems: WebLogic version 5.1.0 SP 8" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
signature = "<%=";
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.js%70" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, signature )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
files = http_get_kb_file_extensions( port: port, host: host, ext: "jsp" );
if(isnull( files )){
	exit( 0 );
}
files = make_list( files );
file = ereg_replace( string: files[0], pattern: "(.*js)p$", replace: "\\1" );
url = NASLString( file, "%70" );
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, signature )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

