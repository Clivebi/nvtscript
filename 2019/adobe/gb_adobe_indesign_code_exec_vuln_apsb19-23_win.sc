CPE = "cpe:/a:adobe:indesign_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814965" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2019-7107" );
	script_bugtraq_id( 107821 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-11 14:52:03 +0530 (Thu, 11 Apr 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe InDesign Arbitrary Code Execution Vulnerability-APSB19-23 (Windows)" );
	script_tag( name: "summary", value: "This host is running Adobe InDesign and is
  prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists de to unsafe hyperlink processing." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application. Failed
  attacks may cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Adobe InDesign versions 14.0.1 and earlier on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 14.0.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/indesign/apsb19-23.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_indesign_detect.sc" );
	script_mandatory_keys( "Adobe/InDesign/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "14.0.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "14.0.2", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

