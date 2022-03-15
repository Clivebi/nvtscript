CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809823" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-9078" );
	script_bugtraq_id( 94569 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 12:04:46 +0530 (Thu, 01 Dec 2016)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2016-91_2016-91) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to an URL redirection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw exists as data: URL can inherit
  wrong origin after an HTTP redirect." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to redirect a URL maliciously, current data suggests
  it does not have any capacity to impact the host system." );
	script_tag( name: "affected", value: "Mozilla Firefox versions 49.0 and 50.0." );
	script_tag( name: "solution", value: "Update to version 50.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-91" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "49.0", test_version2: "50.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "50.0.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

