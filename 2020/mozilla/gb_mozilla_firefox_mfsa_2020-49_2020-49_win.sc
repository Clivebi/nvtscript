CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817524" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2020-26950" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-09 19:42:00 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-10 14:49:59 +0530 (Tue, 10 Nov 2020)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2020-49_2020-49) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to 'Write' side effects
  in 'MCallGetProperty' opcode not accounted." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code on the system." );
	script_tag( name: "affected", value: "Mozilla Firefox version before
  82.0.3 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 82.0.3
  or later, Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-49/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "82.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "82.0.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

