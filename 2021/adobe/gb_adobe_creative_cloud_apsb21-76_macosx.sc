CPE = "cpe:/a:adobe:creative_cloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818537" );
	script_version( "2021-09-24T05:06:20+0000" );
	script_cve_id( "CVE-2021-28613" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-24 05:06:20 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-16 13:01:06 +0530 (Thu, 16 Sep 2021)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Creative Cloud Security Update APSB21-76 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is missing an important security
  update according to Adobe September update." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to creation of temporary
  file in directory with incorrect permissions." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to write arbitrary files on the target system." );
	script_tag( name: "affected", value: "Adobe Creative Cloud 5.4 and earlier versions on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Creative Cloud version
  5.5 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/creative-cloud/apsb21-76.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_creative_cloud_detect_macosx.sc" );
	script_mandatory_keys( "AdobeCreativeCloud/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
cloudVer = infos["version"];
cloudPath = infos["location"];
if(version_is_less( version: cloudVer, test_version: "5.5" )){
	report = report_fixed_ver( installed_version: cloudVer, fixed_version: "5.5", install_path: cloudPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

