CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808202" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-5151" );
	script_bugtraq_id( 68692 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-23 17:16:21 +0530 (Mon, 23 May 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress Revslider Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Revslider plugin and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to arbitrary file or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An insufficient validation of user supplied input via 'client_action'
    parameter in a revslider_ajax_action action to 'wp-admin/admin-ajax.php' script.

  - Insecure direct request to 'revslider_admin.php' script.

  - An insufficient validation of user supplied input via 'img' parameter
    to 'wp-admin/admin-ajax.php' script" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server and
  to obtain sensitive information." );
	script_tag( name: "affected", value: "WordPress Revslider version 4.2.2" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132366" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
url = dir + "/wp-admin/admin-ajax.php?action=revslider_ajax_action&client_action=get_captions_css";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "success\":true", extra_check: make_list( "message\":",
	 "data\":" ) )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

