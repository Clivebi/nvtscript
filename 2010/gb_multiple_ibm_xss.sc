if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100538" );
	script_version( "2021-08-12T09:10:13+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:10:13 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-03-17 13:20:23 +0100 (Wed, 17 Mar 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-0714" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Multiple IBM Products Login Page XSS Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38412" );
	script_xref( name: "URL", value: "http://www.hacktics.com/#view=Resources%7CAdvisory" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21421469" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 10040 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Multiple IBM products are prone to a cross-site scripting (XSS)
  vulnerability because they fail to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "IBM Lotus Web Content Management, WebSphere Portal,
  and Lotus Quickr." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 10040 );
url = "/wps/wcm/webinterface/login/login.jsp";
buf = http_get_cache( port: port, item: url );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
url += "?%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>alert\\('vt-xss-test'\\)</script>", string: buf, icase: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

