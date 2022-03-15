CPE = "cpe:/a:ibm:websphere_portal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810315" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2016-5954" );
	script_bugtraq_id( 93017 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-12-20 15:28:21 +0530 (Tue, 20 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM WebSphere Portal Content Manager Denial Of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  Portal and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in content
  manager which allow uploading temporary files to application without proper
  validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service by uploading temporary files." );
	script_tag( name: "affected", value: "IBM WebSphere Portal 6.1.0 before
  6.1.0.6 CF27, 6.1.5 before 6.1.5.3 CF27, 7.0.0 before 7.0.0.2 CF30,
  8.0.0 before 8.0.0.1 CF21, and 8.5.0 before CF12" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Portal 6.1.0.6
  with Cumulative Fix 27 (CF27), or 6.1.5.3 with Cumulative Fix 27 (CF27), or
  7.0.0.2 with Cumulative Fix 30 (CF30), or 8.0.0.1 with Cumulative Fix 21 (CF21),
  or 8.5.0 with Cumulative Fix 12 (CF12), or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21989993" );
	script_xref( name: "URL", value: "https://exchange.xforce.ibmcloud.com/vulnerabilities/116099" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1036762" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ibm_websphere_portal_detect.sc" );
	script_mandatory_keys( "ibm_websphere_portal/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!webPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!webVer = get_app_version( cpe: CPE, port: webPort )){
	exit( 0 );
}
if( IsMatchRegexp( webVer, "^8\\.5\\.0" ) ){
	if(version_is_less( version: webVer, test_version: "8.5.0.0.12" )){
		fix = "8.5.0.0 CF12";
		VULN = TRUE;
	}
}
else {
	if( IsMatchRegexp( webVer, "^8\\.0\\.0" ) ){
		if(version_is_less( version: webVer, test_version: "8.0.0.1.21" )){
			fix = "8.0.0.1 CF21";
			VULN = TRUE;
		}
	}
	else {
		if( IsMatchRegexp( webVer, "^7\\.0\\.0" ) ){
			if(version_is_less( version: webVer, test_version: "7.0.0.2.30" )){
				fix = "7.0.0.2 CF30";
				VULN = TRUE;
			}
		}
		else {
			if( IsMatchRegexp( webVer, "^6\\.1\\.5" ) ){
				if(version_is_less( version: webVer, test_version: "6.1.5.3.27" )){
					fix = "6.1.5.3 CF27";
					VULN = TRUE;
				}
			}
			else {
				if(IsMatchRegexp( webVer, "^6\\.1\\.0" )){
					if(version_is_less( version: webVer, test_version: "6.1.0.6.27" )){
						fix = "6.1.0.6 CF27";
						VULN = TRUE;
					}
				}
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: webVer, fixed_version: fix );
	security_message( data: report, port: webPort );
	exit( 0 );
}

