CPE = "cpe:/a:adobe:dng_converter";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812211" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-11295" );
	script_bugtraq_id( 101828 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-22 19:47:00 +0000 (Fri, 22 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-11-16 16:38:07 +0530 (Thu, 16 Nov 2017)" );
	script_name( "Adobe DNG Converter Memory Corruption Vulnerability Nov17 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe DNG
  Converter and is prone to a memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to some unspecified memory
  corruption error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  execute arbitrary code in the context of the user running the affected application.
  Failed exploit attempts will likely result in denial-of-service conditions." );
	script_tag( name: "affected", value: "Adobe DNG Converter 9.12.1 and earlier
  versions on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe DNG Converter version 10.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/dng-converter/apsb17-37.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_dng_converter_detect_win.sc" );
	script_mandatory_keys( "Adobe/DNG/Converter/Win/Version" );
	script_xref( name: "URL", value: "http://supportdownloads.adobe.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
adVer = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: adVer, test_version: "9.12.1.790" )){
	report = report_fixed_ver( installed_version: adVer, fixed_version: "10.0", install_path: path );
	security_message( data: report );
	exit( 0 );
}

