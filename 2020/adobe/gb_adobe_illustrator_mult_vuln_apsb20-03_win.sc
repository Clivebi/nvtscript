CPE = "cpe:/a:adobe:illustrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816613" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3710", "CVE-2020-3711", "CVE-2020-3712", "CVE-2020-3713", "CVE-2020-3714" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-30 17:13:00 +0000 (Thu, 30 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-16 15:20:54 +0530 (Thu, 16 Jan 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Illustrator Multiple Vulnerabilities (APSB20-03) - Windows" );
	script_tag( name: "summary", value: "Adobe Illustrator is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory
  corruption errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Adobe Illustrator CC 2020 24.0 and earlier
  versions." );
	script_tag( name: "solution", value: "Update to Adobe Illustrator CC 2020 version
  24.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/illustrator/apsb20-03.html" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_illustrator_detect_win.sc" );
	script_mandatory_keys( "Adobe/Illustrator/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "24.0.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "24.0.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

