if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20252" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-3980" );
	script_bugtraq_id( 15676 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Edgewall Software Trac SQL injection flaw" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_tag( name: "solution", value: "Upgrade to Trac version 0.9.1 or later." );
	script_tag( name: "summary", value: "The remote version of Trac is prone to a SQL injection flaw
  through the ticket query module due to 'group' parameter is not properly sanitized." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/418294/30/0/threaded" );
	script_xref( name: "URL", value: "http://projects.edgewall.com/trac/wiki/ChangeLog" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/trac", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/query?group=/*" );
	buf = http_get( item: url, port: port );
	r = http_keepalive_send_recv( port: port, data: buf, bodyonly: TRUE );
	if(!r){
		continue;
	}
	if(ContainsString( r, "Trac detected an internal error" ) && egrep( pattern: "<title>Oops - .* - Trac<", string: r )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

