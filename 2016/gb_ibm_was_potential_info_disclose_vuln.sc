CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809339" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-5986" );
	script_bugtraq_id( 93013 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-10-03 13:28:39 +0530 (Mon, 03 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Potential Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an improper handling of
  responses under certain conditions." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to gain server identification information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  7.0 before 7.0.0.43, 8.0 before 8.0.0.13, 8.5 before 8.5.5.11, 9.0 before
  9.0.0.2, and Liberty before 16.0.0.3" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) to 7.0.0.43, or 8.0.0.13, or 8.5.5.11, or 9.0.0.2 or Liberty
  Fix 16.0.0.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21990056" );
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
	if(version_is_less( version: wasVer, test_version: "16.0.0.3" )){
		fix = "16.0.0.3";
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

