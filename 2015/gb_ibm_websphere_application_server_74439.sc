CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105283" );
	script_bugtraq_id( 74439 );
	script_cve_id( "CVE-2015-1920" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_name( "IBM WebSphere Application Server Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/74439" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts will likely cause a denial-of-service condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "IBM WebSphere Application Server (WAS) allows remote attackers to execute arbitrary code by sending crafted
instructions in a management-port session." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "IBM WebSphere Application Server is prone to a remote code-execution vulnerability." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS) 6.1 through 6.1.0.47, 7.0 before 7.0.0.39, 8.0 before 8.0.0.11, and 8.5 before 8.5.5.6" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-06-03 09:34:17 +0200 (Wed, 03 Jun 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: vers, test_version: "8.5", test_version2: "8.5.5.5" ) ) {
	fix = "8.5.5.6";
}
else {
	if( version_in_range( version: vers, test_version: "8.0", test_version2: "8.0.0.10" ) ) {
		fix = "8.0.0.11";
	}
	else {
		if( version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.0.38" ) ) {
			fix = "7.0.0.39";
		}
		else {
			if(version_in_range( version: vers, test_version: "6.1", test_version2: "6.1.0.46" )){
				fix = "6.1.0.47";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

