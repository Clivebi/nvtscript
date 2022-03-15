CPE = "cpe:/a:darold:squidclamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103568" );
	script_bugtraq_id( 54663 );
	script_cve_id( "CVE-2012-3501" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 11435 $" );
	script_name( "SquidClamav URL Parsing Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54663" );
	script_xref( name: "URL", value: "http://squidclamav.darold.net/news.html" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-17 15:44:25 +0200 (Mon, 17 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-17 12:15:00 +0200 (Mon, 17 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Denial of Service" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_SquidClamAv_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "SquidClamAv/installed" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
information." );
	script_tag( name: "summary", value: "SquidClamav is prone to a denial-of-service vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause the daemon to crash,
denying service to legitimate users." );
	script_tag( name: "affected", value: "SquidClamav versions prior to 5.8 and 6.7 are vulnerable." );
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
url = dir + "/clwarn.cgi?url=<vuln-test>";
if(http_vuln_check( port: port, url: url, pattern: "The requested URL <vuln-test>", extra_check: "contains the virus" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

