CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809853" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_cve_id( "CVE-2016-4027" );
	script_bugtraq_id( 91354 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-19 15:46:00 +0000 (Fri, 19 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-01-02 15:28:47 +0530 (Mon, 02 Jan 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange AppSuite 'authentication cookies' Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Open-Xchange (OX)
  AppSuite and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the system may store
  authentication cookies on the target user's system after a session has
  terminated." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to access cookies that contain authentication information." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite versions
  7.6.2-rev0 to 7.6.2-rev42, 7.6.3-rev0 - 7.6.3-rev10,
  7.8.0-rev0 - 7.8.0-rev22, 7.8.1-rev0 - 7.8.1-rev9" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.8.1-rev10, or 7.6.2-rev43, or 7.8.0-rev23, or 7.6.3-rev11, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1036157" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/137599" );
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
	if( IsMatchRegexp( oxVer, "^(7\\.8\\.1)" ) && version_is_less( version: oxVer, test_version: "7.8.1.10" ) ){
		fix = "7.8.1-rev10";
		VULN = TRUE;
	}
	else {
		if( IsMatchRegexp( oxVer, "^(7\\.6\\.2)" ) && version_is_less( version: oxVer, test_version: "7.6.2.43" ) ){
			fix = "7.6.2-rev43";
			VULN = TRUE;
		}
		else {
			if( IsMatchRegexp( oxVer, "^(7\\.6\\.3)" ) && version_is_less( version: oxVer, test_version: "7.6.3.11" ) ){
				fix = "7.6.3-rev11";
				VULN = TRUE;
			}
			else {
				if(IsMatchRegexp( oxVer, "^(7\\.8\\.0)" ) && version_is_less( version: oxVer, test_version: "7.8.0.23" )){
					fix = "7.8.0-rev23";
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

