CPE = "cpe:/a:sixapart:movable_type";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100430" );
	script_version( "$Revision: 12861 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-21 10:53:04 +0100 (Fri, 21 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-01-06 18:07:55 +0100 (Wed, 06 Jan 2010)" );
	script_bugtraq_id( 37638 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Movable Type Unspecified Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37638" );
	script_xref( name: "URL", value: "http://www.movabletype.jp/blog/movable_type_501.html" );
	script_xref( name: "URL", value: "http://www.movabletype.org/" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN09872874/index.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mt_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "movabletype/detected" );
	script_tag( name: "solution", value: "The vendor has released fixes. Please see the references for more
information." );
	script_tag( name: "summary", value: "Movable Type is prone to an unspecified security-bypass vulnerability.

Very little is known about this issue at this time (06.01.2010). We will update this BID as more information
emerges.

This issue affects versions prior to 4.27 and 5.01." );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( IsMatchRegexp( vers, "^5\\." ) ){
	if(version_is_less( version: vers, test_version: "5.01" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.01" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: vers, test_version: "4.27" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.01" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

