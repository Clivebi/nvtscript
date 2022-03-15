CPE = "cpe:/a:adobe:animate";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817923" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-21052" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 16:59:00 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-11 10:38:28 +0530 (Thu, 11 Feb 2021)" );
	script_name( "Adobe Animate Code Execution Vulnerability (APSB21-11) - Windows" );
	script_tag( name: "summary", value: "Adobe Animate is prone to a code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an out-of-bounds write
  error." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to
  execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Adobe Animate 21.0.2 and earlier versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Animate 21.0.3 or later. Please
  see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/animate/apsb21-11.html" );
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
if(version_is_less( version: vers, test_version: "21.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "21.0.3", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

