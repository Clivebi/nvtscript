CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809349" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_cve_id( "CVE-2016-5983" );
	script_bugtraq_id( 93162 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:30:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2016-10-13 14:40:54 +0530 (Thu, 13 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Code Execution vulnerability Oct16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an improper validation
  of a serialized object from untrusted sources." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  authenticated users to execute arbitrary Java code." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  7.0 before 7.0.0.43, 8.0 before 8.0.0.13, 8.5 before 8.5.5.11, 9.0 before
  9.0.0.2, and Liberty before 16.0.0.4" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) to 7.0.0.43, or 8.0.0.13, or 8.5.5.11, or 9.0.0.2 or Liberty
  Fix 16.0.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www-01.ibm.com/support/docview.wss?uid=swg21990060" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
liberty = get_kb_item( "ibm_websphere_application_server/liberty/profile/installed" );
if( liberty ){
	if(version_is_less( version: wasVer, test_version: "16.0.0.4" )){
		fix = "16.0.0.4";
		VULN = TRUE;
	}
}
else {
	if( version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.41" ) ){
		fix = "7.0.0.43";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.12" ) ){
			fix = "8.0.0.13";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.10" ) ){
				fix = "8.5.5.11";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: wasVer, test_version: "9.0", test_version2: "9.0.0.1" )){
					fix = "9.0.0.2";
					VULN = TRUE;
				}
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

