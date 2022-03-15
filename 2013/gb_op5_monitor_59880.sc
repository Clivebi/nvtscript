CPE = "cpe:/a:op5:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103712" );
	script_bugtraq_id( 59880 );
	script_version( "2020-04-21T11:03:03+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "op5 Monitor Multiple Information Disclosure and Security Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/59880" );
	script_xref( name: "URL", value: "http://www.op5.com/" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-05-16 11:45:26 +0200 (Thu, 16 May 2013)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_op5_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OP5/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "op5 Monitor is prone to multiple information-disclosure and security-
bypass vulnerabilities.

An attacker may exploit these issues to obtain sensitive information
and bypass certain security restrictions.

op5 Monitor versions prior to 6.1.0 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less( version: vers, test_version: "6.1.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "6.1.0" );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

