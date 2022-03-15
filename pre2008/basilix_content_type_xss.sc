CPE = "cpe:/a:basilix:basilix_webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14307" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 10666 );
	script_name( "BasiliX Content-Type XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2004 George A. Theall" );
	script_dependencies( "basilix_detect.sc" );
	script_mandatory_keys( "basilix/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to BasiliX version 1.1.1 fix1 or later." );
	script_tag( name: "summary", value: "The remote web server contains a PHP script which is vulnerable to a cross
site scripting issue.

Description :

The remote host appears to be running BasiliX version 1.1.1 or lower. Such versions are vulnerable to a
cross-scripting attack whereby an attacker may be able to cause a victim to unknowingly run arbitrary Javascript
code simply by reading a MIME message with a specially crafted Content-Type header." );
	script_xref( name: "URL", value: "http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt" );
	script_xref( name: "URL", value: "http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "1.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.1 fix1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

