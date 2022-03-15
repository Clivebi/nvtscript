CPE = "cpe:/a:darold:squidclamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103567" );
	script_bugtraq_id( 55293 );
	script_cve_id( "CVE-2012-4667" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 11435 $" );
	script_name( "SquidClamav Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55293" );
	script_xref( name: "URL", value: "http://squidclamav.darold.net/news.html" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-17 15:44:25 +0200 (Mon, 17 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-17 11:57:49 +0200 (Mon, 17 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_SquidClamAv_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "SquidClamAv/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "SquidClamav is prone to multiple cross-site scripting vulnerabilities
because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks." );
	script_tag( name: "affected", value: "SquidClamav versions prior to 5.8 are affected." );
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
url = dir + "/clwarn.cgi?url=<script>alert(/xss-test/)</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\)</script>", check_header: TRUE, extra_check: "contains the virus" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

