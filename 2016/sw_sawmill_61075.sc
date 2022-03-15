CPE = "cpe:/a:sawmill:sawmill";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111083" );
	script_version( "2019-09-07T11:55:45+0000" );
	script_tag( name: "last_modification", value: "2019-09-07 11:55:45 +0000 (Sat, 07 Sep 2019)" );
	script_tag( name: "creation_date", value: "2016-02-02 17:00:00 +0100 (Tue, 02 Feb 2016)" );
	script_bugtraq_id( 61075 );
	script_cve_id( "CVE-2013-4947" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Sawmill < 8.6.3 Unspecified Remote Security Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61075" );
	script_xref( name: "URL", value: "http://www.sawmill.net/version_history8.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_dependencies( "gb_sawmill_detect.sc" );
	script_mandatory_keys( "sawmill/installed" );
	script_tag( name: "solution", value: "An update is available. Please see the references for details." );
	script_tag( name: "summary", value: "Sawmill is prone to an unspecified remote security vulnerability." );
	script_tag( name: "impact", value: "Little is known about this issue or its effects at this time." );
	script_tag( name: "affected", value: "Sawmill versions prior to 8.6.3 are vulnerable." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "8.6.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.6.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

