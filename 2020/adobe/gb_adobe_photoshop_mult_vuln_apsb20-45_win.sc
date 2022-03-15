if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817252" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9683", "CVE-2020-9686", "CVE-2020-9684", "CVE-2020-9685", "CVE-2020-9687" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-23 20:50:00 +0000 (Thu, 23 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-27 13:50:03 +0530 (Mon, 27 Jul 2020)" );
	script_name( "Adobe Photoshop CC Multiple Vulnerabilities (APSB20-45) - Windows" );
	script_tag( name: "summary", value: "Adobe Photoshop CC is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple out-of-bounds read error.

  - Multiple out-of-bounds write error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to sensitive information and execute arbitrary
  code on the system." );
	script_tag( name: "affected", value: "Adobe Photoshop CC 2019 20.0.9 and earlier
  and Adobe Photoshop 2020 21.2 and earlier versions." );
	script_tag( name: "solution", value: "Update to Adobe Photoshop CC 2019 20.0.10
  or Photoshop CC 2020 21.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/photoshop/apsb20-45.html" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_photoshop_detect.sc" );
	script_mandatory_keys( "Adobe/Photoshop/Installed" );
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
	if(version_is_less( version: vers, test_version: "21.2.1" )){
		fix = "21.2.1";
		installed_ver = "Adobe Photoshop CC 2020";
	}
}
else {
	if(IsMatchRegexp( vers, "^20\\." )){
		if(version_is_less( version: vers, test_version: "20.0.10" )){
			fix = "20.0.10";
			installed_ver = "Adobe Photoshop CC 2019";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: installed_ver + " " + vers, fixed_version: fix, install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

