CPE = "cpe:/a:cisco:unified_communications_manager_im_and_presence_service";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105545" );
	script_bugtraq_id( 76944 );
	script_cve_id( "CVE-2015-6310" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-04-22T08:55:01+0000" );
	script_name( "Cisco Unified Communications Manager IM and Presence Service EST API Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/76944" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20151002-CVE-2015-6310" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to restart the affected service and cause a denial of service condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "summary", value: "Cisco Unified Communications Manager IM and Presence Service is prone to a denial-of-service vulnerability." );
	script_tag( name: "affected", value: "Versions 10.5 before 10.5(2.23000.1), 11.0 before 11.0(1.11000.1) and 9.1 before 9.1(1.81900.5)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-02-15 12:13:16 +0100 (Mon, 15 Feb 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_cucmim_version.sc" );
	script_mandatory_keys( "cisco/cucmim/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
vers = str_replace( string: vers, find: "-", replace: "." );
if(IsMatchRegexp( vers, "^10\\.5" )){
	if(version_is_less( version: vers, test_version: "10.5.2.23000.1" )){
		fix = "10.5(2.23000.1)";
	}
}
if(IsMatchRegexp( vers, "^11\\.0" )){
	if(version_is_less( version: vers, test_version: "11.0.1.11000.1" )){
		fix = "11.0(1.11000.1)";
	}
}
if(IsMatchRegexp( vers, "^9\\.1" )){
	if(version_is_less( version: vers, test_version: "9.1.1.81900.5" )){
		fix = "9.1(1.81900.5)";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

