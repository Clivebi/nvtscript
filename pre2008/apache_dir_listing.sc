CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10704" );
	script_version( "2021-02-25T13:36:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3009 );
	script_xref( name: "OWASP", value: "OWASP-CM-004" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-0731" );
	script_name( "Apache HTTP Server Directory Listing" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Matt Moore" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_tag( name: "solution", value: "Unless it is required, turn off Indexing by making the appropriate changes to your
  httpd.conf file." );
	script_tag( name: "summary", value: "By making a request to the Apache HTTP server ending in '?M=A' it is sometimes possible to obtain a
  directory listing even if an index.html file is present.

  It appears that it is possible to retrieve a directory listing from the root of the Apache
  HTTP server being tested. However, this could be because there is no 'index.html' or similar
  default file present." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Apache" )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, "Index of " )){
	exit( 0 );
}
url = "/?M=A";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( res, "Index of " ) && ContainsString( res, "Last modified" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

