CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806890" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2014-4770", "CVE-2014-4816" );
	script_bugtraq_id( 69980, 69981 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:50 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities-02 Mar16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to improper
  validation of input in the Administrative Console." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to obtain sensitive information, perform cross-site scripting attacks,
  perform session injection and other malicious activities, also to inject script
  into a victim's Web browser within the security context of the hosting Web site." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  6.x through 6.1.0.47, 7.0 before 7.0.0.35, 8.0 before 8.0.0.10,
  and 8.5 before 8.5.5.4" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.35, or 8.0.0.10, or 8.5.5.4, or later.
  For version 6.1.0.47 and earlier 'Apply Interim Fix PI23055'" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21682767" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21671835" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: wasVer, test_version: "6", test_version2: "6.1.0.47" ) ){
	fix = "Apply Interim Fix PI23055";
	VULN = TRUE;
}
else {
	if( version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.34" ) ){
		fix = "7.0.0.35";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.9" ) ){
			fix = "8.0.0.10";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.3" )){
				fix = "8.5.5.4";
				VULN = TRUE;
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

