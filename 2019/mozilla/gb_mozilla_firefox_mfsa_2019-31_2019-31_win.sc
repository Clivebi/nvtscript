CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815473" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-11754" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-19 15:18:57 +0530 (Thu, 19 Sep 2019)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2019-31_2019-31) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to a hijacking vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to not giving any user
  notification when the pointer lock is enabled by a website though
  'requestPointerLock' function." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  hijack the mouse pointer and confuse users." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 69.0.1 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 69.0.1
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-31" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
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
if(version_is_less( version: vers, test_version: "69.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "69.0.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

