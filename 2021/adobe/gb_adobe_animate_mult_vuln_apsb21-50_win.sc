CPE = "cpe:/a:adobe:animate";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818327" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-28630", "CVE-2021-28619", "CVE-2021-28617", "CVE-2021-28618", "CVE-2021-28621", "CVE-2021-28620", "CVE-2021-28629", "CVE-2021-28622" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-30 20:24:00 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 10:10:36 +0530 (Thu, 10 Jun 2021)" );
	script_name( "Adobe Animate Multiple Vulnerabilities (APSB21-50) - Windows" );
	script_tag( name: "summary", value: "Adobe Animate is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple out-of-bounds read errors.

  - A Heap-based Buffer Overflow.

  - An Out-of-bounds Write error." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to
  execute arbitrary code and disclose sensitive information on the affected
  system." );
	script_tag( name: "affected", value: "Adobe Animate 21.0.6 and earlier versions on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Animate 21.0.7 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/animate/apsb21-50.html" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_animate_detect_win.sc" );
	script_mandatory_keys( "Adobe/Animate/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "21.0.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "21.0.7", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

