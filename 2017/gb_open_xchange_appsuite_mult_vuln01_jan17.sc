CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809846" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2016-6847", "CVE-2016-6848", "CVE-2016-6850", "CVE-2016-6852", "CVE-2016-6842", "CVE-2016-6843", "CVE-2016-6844", "CVE-2016-6845" );
	script_bugtraq_id( 93457, 93460, 93459 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-16 17:03:00 +0000 (Fri, 16 Dec 2016)" );
	script_tag( name: "creation_date", value: "2017-01-02 13:58:15 +0530 (Mon, 02 Jan 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Vulnerabilities -01 Jan17" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - An improper validation of input passed to 'contact names' parameter.

  - An improper validation of input passed to 'Users names' parameter.

  - Script code within hyperlinks at HTML E-Mails is not getting correctly
    sanitized when using base64 encoded 'data' resources.

  - An improper validation of XML structure.

  - Users can provide local file paths to the RSS reader. The response and error
    code give hints about whether the provided file exists or not.

  - An improper sanitization of user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary script code in the browser of an unsuspecting user in the
  context of the affected application. This may let the attacker steal cookie-based
  authentication credentials and bypass certain security restrictions to perform
  unauthorized actions. Attackers can also exploit this issue to obtain sensitive
  information that may aid in further attacks." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite version
  7.8.2-rev0 - 7.8.2-rev7,
  7.6.2-rev0 - 7.6.2-rev46." );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.8.2-rev8, or 7.6.2-rev47, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://software.open-xchange.com/OX6/6.22/doc/Release_Notes_for_Patch_Release_3522_7.8.2_2016-08-29.pdf" );
	script_xref( name: "URL", value: "https://software.open-xchange.com/OX6/6.22/doc/Release_Notes_for_Patch_Release_3518_7.6.2_2016-08-29.pdf" );
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
	if( IsMatchRegexp( oxVer, "^(7\\.8\\.2)" ) && version_is_less( version: oxVer, test_version: "7.8.2.8" ) ){
		fix = "7.8.2-rev8";
		VULN = TRUE;
	}
	else {
		if(IsMatchRegexp( oxVer, "^(7\\.6\\.2)" ) && version_is_less( version: oxVer, test_version: "7.6.2.47" )){
			fix = "7.6.2-rev47";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: oxVer, fixed_version: fix );
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

