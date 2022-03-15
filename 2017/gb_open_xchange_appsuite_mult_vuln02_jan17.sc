CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809847" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2016-4046", "CVE-2016-4045", "CVE-2016-4026" );
	script_bugtraq_id( 91359, 91356, 91357 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-19 15:46:00 +0000 (Fri, 19 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-01-02 13:59:09 +0530 (Mon, 02 Jan 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Vulnerabilities -02 Jan17" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - An improper validation of input passed to API calls.

  - An improper validation of input passed RSS reader of App Suite.

  - The content sanitizer component has an issue with filtering malicious content
    in case invalid HTML code is provided." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary script code in the browser of an unsuspecting user in the
  context of the affected application. This may let the attacker steal cookie-based
  authentication credentials and bypass certain security restrictions to perform
  unauthorized actions, insert and display spoofed content, which may aid in
  further attacks." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite versions
  7.6.2-rev0 - 7.6.2-rev53,
  7.6.3-rev0 - 7.6.3-rev10,
  7.8.0-rev0 - 7.8.0-rev29,
  7.8.1-rev0 - 7.8.1-rev10" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.6.2-rev54, or 7.6.3-rev11, or 7.8.0-rev30, or 7.8.1-rev11, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/538732/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!oxPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!oxVer = get_app_version( cpe: CPE, port: oxPort )){
	exit( 0 );
}
oxRev = get_kb_item( "open_xchange_appsuite/" + oxPort + "/revision" );
if(oxRev){
	oxVer = oxVer + "." + oxRev;
	if( IsMatchRegexp( oxVer, "^(7\\.8\\.0)" ) && version_is_less( version: oxVer, test_version: "7.8.0.30" ) ){
		fix = "7.8.0-rev30";
		VULN = TRUE;
	}
	else {
		if( IsMatchRegexp( oxVer, "^(7\\.8\\.1)" ) && version_is_less( version: oxVer, test_version: "7.8.1.11" ) ){
			fix = "7.8.1-rev11";
			VULN = TRUE;
		}
		else {
			if( IsMatchRegexp( oxVer, "^(7\\.6\\.2)" ) && version_is_less( version: oxVer, test_version: "7.6.2.54" ) ){
				fix = "7.6.2-rev54";
				VULN = TRUE;
			}
			else {
				if(IsMatchRegexp( oxVer, "^(7\\.6\\.3)" ) && version_is_less( version: oxVer, test_version: "7.6.3.11" )){
					fix = "7.6.3-rev11";
					VULN = TRUE;
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: oxVer, fixed_version: fix );
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

