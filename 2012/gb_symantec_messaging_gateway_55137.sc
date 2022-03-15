CPE = "cpe:/a:symantec:messaging_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103613" );
	script_bugtraq_id( 55137 );
	script_cve_id( "CVE-2012-0308" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-22T08:55:01+0000" );
	script_name( "Symantec Messaging Gateway Cross Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55137" );
	script_tag( name: "last_modification", value: "2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-12-03 10:22:01 +0100 (Mon, 03 Dec 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_messaging_gateway_detect.sc" );
	script_mandatory_keys( "symantec_smg/detected" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the reference for more
  details." );
	script_tag( name: "summary", value: "Symantec Messaging Gateway is prone to a cross-site request-forgery
  vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue may allow a remote attacker to perform certain
  unauthorized actions and gain access to the affected application. Other attacks are also possible." );
	script_tag( name: "affected", value: "Symantec Messaging Gateway versions before 10.0 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(vers = get_app_version( cpe: CPE, nofork: TRUE )){
	if(version_is_less( version: vers, test_version: "10.0.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "10.0.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

