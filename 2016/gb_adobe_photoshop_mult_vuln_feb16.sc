if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806869" );
	script_version( "2020-05-13T14:08:32+0000" );
	script_cve_id( "CVE-2016-0951", "CVE-2016-0952", "CVE-2016-0953" );
	script_bugtraq_id( 83114 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-13 14:08:32 +0000 (Wed, 13 May 2020)" );
	script_tag( name: "creation_date", value: "2016-02-15 13:37:52 +0530 (Mon, 15 Feb 2016)" );
	script_name( "Adobe Photoshop CC Multiple Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Photoshop
  CC and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to
  multiple memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service
  (memory corruption) via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Photoshop CC 2014 before 15.2.4,
  Photoshop CC 2015 before 16.1.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Photoshop CC version
  16.1.2 (2015.1.2) or 15.2.4 (2014.2.4) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/photoshop/apsb16-03.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_photoshop_detect.sc" );
	script_mandatory_keys( "Adobe/Photoshop/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:photoshop_cc2015",
	 "cpe:/a:adobe:photoshop_cc2014" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_is_less( version: vers, test_version: "16.1.2" ) ){
	fix = "16.1.2 (2015.1.2)";
}
else {
	if(version_is_less( version: vers, test_version: "15.2.4" )){
		fix = "15.2.4 (2014.2.4)";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

