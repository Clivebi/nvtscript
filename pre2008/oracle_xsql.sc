if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10594" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2001-0126" );
	script_bugtraq_id( 2295 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Oracle XSQL Stylesheet Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Oracle/banner" );
	script_tag( name: "summary", value: "The Oracle XSQL Servlet allows arbitrary Java code to be executed by an attacker by supplying
  the URL of a malicious XSLT stylesheet when making a request to an XSQL page." );
	script_tag( name: "solution", value: "Until Oracle changes the default behavior for the XSQL servlet to disallow client supplied stylesheets,
  you can workaround this problem as follows. Add allow-client-style='no' on the document element of every xsql page on
  your server.

  This plug-in tests for this vulnerability using a sample page, airport.xsql, which is supplied with the Oracle XSQL
  servlet. Sample code should always be removed from production servers." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/xsql/demo/airport/airport.xsql?xml-stylesheet=none";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "cvsroot" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

