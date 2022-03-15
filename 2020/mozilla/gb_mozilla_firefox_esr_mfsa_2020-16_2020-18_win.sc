CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817002" );
	script_version( "2021-08-16T14:00:55+0000" );
	script_cve_id( "CVE-2020-1238", "CVE-2020-6831", "CVE-2020-1239" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 14:00:55 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-23 19:37:00 +0000 (Thu, 23 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-05-06 17:57:31 +0530 (Wed, 06 May 2020)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2020-16_2020-18) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to a buffer
  overflow in SCTP chunk input validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to conduct a denial-of-service or execute arbitrary code
  on affected system." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 68.8 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version 68.8
  or later, Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-17/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "68.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "68.8", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

