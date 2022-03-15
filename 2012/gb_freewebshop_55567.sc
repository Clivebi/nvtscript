CPE = "cpe:/a:freewebshop:freewebshop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103570" );
	script_bugtraq_id( 55567 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "FreeWebshop Multiple SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55567" );
	script_xref( name: "URL", value: "http://www.freewebshop.org" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-09-18 13:18:37 +0200 (Tue, 18 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "FreeWebShop_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "FreeWebshop/installed" );
	script_tag( name: "summary", value: "FreeWebshop is prone to multiple SQL-injection and cross-site scripting
vulnerabilities because it fails to sufficiently sanitize user-supplied input.

Exploiting these vulnerabilities could allow an attacker to steal cookie-based authentication credentials,
compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.

FreeWebshop 2.2.9 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
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
url = dir + "/index.php?page=browse&searchfor=<script>alert(/xss-test/)</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

