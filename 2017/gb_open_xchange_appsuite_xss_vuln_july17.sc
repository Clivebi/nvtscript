CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810973" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2016-6846" );
	script_bugtraq_id( 93458 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-04 15:20:00 +0000 (Tue, 04 Apr 2017)" );
	script_tag( name: "creation_date", value: "2017-07-05 11:26:23 +0530 (Wed, 05 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Cross Site Scripting Vulnerability July17" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  sanitization of user supplied input while processing requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected application. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite frontend
  before 7.6.2-rev47, 7.8.0 before 7.8.0-rev30, and 7.8.2 before 7.8.2-rev8." );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.6.2-rev47 or 7.8.0-rev30 or 7.8.2-rev8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/93458" );
	script_xref( name: "URL", value: "https://vuldb.com/?id.99054" );
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
	if( version_is_less( version: oxVer, test_version: "7.6.2.47" ) ){
		fix = "7.6.2-rev47";
	}
	else {
		if( IsMatchRegexp( oxVer, "^(7\\.8\\.0)" ) && version_is_less( version: oxVer, test_version: "7.8.0.30" ) ){
			fix = "7.8.0-rev30";
		}
		else {
			if(IsMatchRegexp( oxVer, "^(7\\.8\\.2)" ) && version_is_less( version: oxVer, test_version: "7.8.2.8" )){
				fix = "7.8.2-rev8";
			}
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: oxVer, fixed_version: fix );
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

