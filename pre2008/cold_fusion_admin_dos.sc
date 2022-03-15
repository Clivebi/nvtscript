if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10581" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1314 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2000-0538" );
	script_name( "Cold Fusion Administration Page Overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Use HTTP basic authentication to restrict access to this page or
  remove it entirely if remote administration is not a requirement.

  A patch should be available from the vendor." );
	script_tag( name: "summary", value: "A denial of service vulnerability exists within the Allaire
  ColdFusion web application server (version 4.5.1 and earlier) which allows an
  attacker to overwhelm the web server and deny legitimate web page requests." );
	script_tag( name: "impact", value: "By downloading and altering the login HTML form an attacker can
  send overly large passwords (> 40.0000 chars) to the server, causing it to stop responding." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/CFIDE/administrator/index.cfm";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "PasswordProvided" ) && !ContainsString( res, "cf50" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

