CPE = "cpe:/a:adobe:acrobat_dc_continuous";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817866" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-29075" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-22 20:03:00 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-12-10 11:06:38 +0530 (Thu, 10 Dec 2020)" );
	script_name( "Adobe Acrobat DC (Continuous) Security Update (APSB20-75) - Windows" );
	script_tag( name: "summary", value: "Adobe Acrobat DC (Continuous Track) is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper input validation
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose sensitive information on victim's system." );
	script_tag( name: "affected", value: "Adobe Acrobat DC (Continuous Track) prior
  to version 2020.013.20074." );
	script_tag( name: "solution", value: "Update Adobe Acrobat DC (Continuous)
  to version 2020.013.20074 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb20-75.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_dc_cont_detect_win.sc" );
	script_mandatory_keys( "Adobe/AcrobatDC/Continuous/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "20.0", test_version2: "20.013.20073" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "20.013.20074(2020.013.20074)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

