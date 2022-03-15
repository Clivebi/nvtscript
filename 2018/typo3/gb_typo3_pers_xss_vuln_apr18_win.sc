CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813314" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-6905" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-09 17:53:00 +0000 (Wed, 09 May 2018)" );
	script_tag( name: "creation_date", value: "2018-04-23 15:18:11 +0530 (Mon, 23 Apr 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Typo3 Persistent XSS Vulnerability (Apr 2018) - Windows" );
	script_tag( name: "summary", value: "Typo3 is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  sanitization of user supplied input in the page module." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute a script on victim's Web browser within the security
  context of the hosting Web site." );
	script_tag( name: "affected", value: "Typo3 CMS version 9.1.0 and versions before 8.7.11 on windows." );
	script_tag( name: "solution", value: "Update to 8.7.11 or later for all versions before 8.7.11. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://github.com/pradeepjairamani/TYPO3-XSS-POC" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "TYPO3/installed", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, version_regex: "[0-9]+\\.[0-9]+\\.[0-9]+", exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( vers == "9.1.0" ){
	fix = "None available";
}
else {
	if(version_is_less( version: vers, test_version: "8.7.11" )){
		fix = "8.7.11";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

