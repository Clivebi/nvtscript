CPE = "cpe:/a:adobe:dreamweaver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817920" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-21055" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 16:50:00 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-11 10:38:28 +0530 (Thu, 11 Feb 2021)" );
	script_name( "Adobe Dreamweaver Information Disclosure Vulnerability (APSB21-13) - Windows" );
	script_tag( name: "summary", value: "Adobe Dreamweaver is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to presence of an
  uncontrolled search path element." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to
  disclose sensitive information on the affected system." );
	script_tag( name: "affected", value: "Adobe Dreamweaver prior to 20.2 and 21.0
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Dreamweaver 20.2.1 or 21.1
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/dreamweaver/apsb21-13.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_require_ports( 139, 445 );
	script_dependencies( "secpod_adobe_dreamweaver_detect.sc" );
	script_mandatory_keys( "Adobe/Dreamweaver/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
AppVer = fetch_file_version( sysPath: path, file_name: "Dreamweaver.exe" );
if(!AppVer){
	AppVer = fetch_file_version( sysPath: path, file_name: "Adobe Dreamweaver CC 2018\\Dreamweaver.exe" );
}
if(!AppVer){
	exit( 0 );
}
if( version_is_less( version: AppVer, test_version: "20.2.1" ) ){
	fix = "20.2.1";
}
else {
	if(AppVer == "21.0"){
		fix = "21.1";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: AppVer, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

