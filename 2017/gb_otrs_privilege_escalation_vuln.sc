CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812273" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-17476" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-12-26 13:32:26 +0530 (Tue, 26 Dec 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OTRS Framework Privilege Escalation Vulnerability (OSA-2017-10)" );
	script_tag( name: "summary", value: "The host is installed with OTRS Framework
  and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as when an attacker sends a
  specially prepared email to an OTRS system while system has cookie support
  disabled, a logged in agent clicking a link in this email will leak the session
  information to external systems." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to hijack web sessions and consequently gain privileges via a
  crafted email." );
	script_tag( name: "affected", value: "Open Ticket Request System (OTRS) 4.0.x
  before 4.0.28, 5.0.x before 5.0.26, and 6.0.x before 6.0.3" );
	script_tag( name: "solution", value: "Upgrade to 6.0.3 or 4.0.28 or 5.0.26
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2017-10-security-update-otrs-framework" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!otPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: otPort, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( ( IsMatchRegexp( vers, "^(4\\.0)" ) ) && ( version_is_less( version: vers, test_version: "4.0.28" ) ) ){
	fix = "4.0.28";
}
else {
	if( ( IsMatchRegexp( vers, "^(5\\.0)" ) ) && ( version_is_less( version: vers, test_version: "5.0.26" ) ) ){
		fix = "5.0.26";
	}
	else {
		if(( IsMatchRegexp( vers, "^(6\\.0)" ) ) && ( version_is_less( version: vers, test_version: "6.0.3" ) )){
			fix = "6.0.3";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: otPort );
	exit( 0 );
}
exit( 0 );

