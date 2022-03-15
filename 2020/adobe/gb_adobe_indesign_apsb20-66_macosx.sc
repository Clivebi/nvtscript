CPE = "cpe:/a:adobe:indesign_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817605" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-24421" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-28 13:15:00 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-10-21 11:26:46 +0530 (Wed, 21 Oct 2020)" );
	script_name( "Adobe InDesign RCE Vulnerability (APSB20-66) - Mac OS X" );
	script_tag( name: "summary", value: "Adobe InDesign is prone to RCE vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The flaw exists due to presence of a memory
  corruption error." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Adobe InDesign 15.1.2 and earlier versions." );
	script_tag( name: "solution", value: "Update to Adobe InDesign 16.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/media-encoder/apsb20-66.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_indesign_server_detect_macosx.sc" );
	script_mandatory_keys( "InDesign/Server/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "16.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "16.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

