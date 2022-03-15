if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817601" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-24420" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 18:05:00 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-21 11:26:46 +0530 (Wed, 21 Oct 2020)" );
	script_name( "Adobe Photoshop CC RCE Vulnerability (APSB20-63) - Mac OS X" );
	script_tag( name: "summary", value: "Adobe Photoshop CC is prone to RCE vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The flaw exists due to presence of an
  uncontrolled search path element." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Adobe Photoshop CC 2019 20.0.10 and earlier
  and Adobe Photoshop 2020 21.2.2 and earlier versions." );
	script_tag( name: "solution", value: "Update to Adobe Photoshop CC 2020 21.2.3
  or Photoshop CC 2021 22.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/photoshop/apsb20-63.html" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_photoshop_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Photoshop/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:photoshop_cc2019",
	 "cpe:/a:adobe:photoshop" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^21\\." ) ){
	if(version_is_less( version: vers, test_version: "21.2.3" )){
		fix = "21.2.3";
		installed_ver = "Adobe Photoshop CC 2020";
	}
}
else {
	if(IsMatchRegexp( vers, "^20\\." )){
		fix = "Adobe Photoshop CC 2020 or Adobe Photoshop 2021";
		installed_ver = "Adobe Photoshop CC 2019";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: installed_ver + " " + vers, fixed_version: fix, install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

