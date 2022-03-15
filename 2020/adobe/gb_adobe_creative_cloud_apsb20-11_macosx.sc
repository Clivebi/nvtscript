CPE = "cpe:/a:adobe:creative_cloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816728" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3808" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-27 19:58:00 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-27 18:27:46 +0530 (Fri, 27 Mar 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Creative Cloud Security Update APSB20-11 (Mac OS X)" );
	script_tag( name: "summary", value: "Adobe Creative cloud is prone to an arbitrary file deletion vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Time-of-check to
  time-of-use (TOCTOU) race condition." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to delete arbitrary files on the target system." );
	script_tag( name: "affected", value: "Adobe Creative Cloud 5.0 and earlier versions." );
	script_tag( name: "solution", value: "Update to Adobe Creative Cloud version
  5.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/creative-cloud/apsb20-11.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

