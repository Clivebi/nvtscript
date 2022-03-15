if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813870" );
	script_version( "2021-06-01T06:00:15+0200" );
	script_cve_id( "CVE-2018-12810", "CVE-2018-12811" );
	script_bugtraq_id( 105123 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-01 06:00:15 +0200 (Tue, 01 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-26 01:05:00 +0000 (Fri, 26 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-08-23 10:51:12 +0530 (Thu, 23 Aug 2018)" );
	script_name( "Adobe Photoshop CC Multiple Memory Corruption Vulnerabilities - APSB18-28 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Photoshop
  CC and is prone to multiple memory corruption vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  unspecified memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code in the context of the user running the affected
  application. Failed exploit attempts will likely result in denial-of-service
  conditions." );
	script_tag( name: "affected", value: "Adobe Photoshop CC 2017 18.1.5 and earlier
  and Adobe Photoshop CC 2018 19.1.5 and earlier versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Photoshop CC 2017
  18.1.6 or Photoshop CC 2018 19.1.6 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/photoshop/apsb18-28.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_photoshop_detect.sc" );
	script_mandatory_keys( "Adobe/Photoshop/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:photoshop_cc2017",
	 "cpe:/a:adobe:photoshop_cc2018" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^18\\." ) ){
	if(version_is_less_equal( version: vers, test_version: "18.1.5" )){
		fix = "18.1.6";
		installed_ver = "Adobe Photoshop CC 2017";
	}
}
else {
	if(IsMatchRegexp( vers, "^19\\." )){
		if(version_is_less_equal( version: vers, test_version: "19.1.5" )){
			fix = "19.1.6";
			installed_ver = "Adobe Photoshop CC 2018";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: installed_ver + " " + vers, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

