CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815146" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-11708" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-15 18:15:00 +0000 (Thu, 15 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-06-21 12:26:30 +0530 (Fri, 21 Jun 2019)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2019-19_2019-20) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an insufficient vetting
  of parameters passed with the Prompt:Open IPC message between child and parent
  processes." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass sandbox restrictions." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 60.7.2 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version 60.7.2
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-19/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "60.7.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "60.7.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

