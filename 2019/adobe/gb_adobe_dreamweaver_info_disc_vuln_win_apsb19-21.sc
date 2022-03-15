CPE = "cpe:/a:adobe:dreamweaver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814964" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_cve_id( "CVE-2019-7097" );
	script_bugtraq_id( 107825 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-11 13:56:56 +0530 (Thu, 11 Apr 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Dreamweaver Information Disclosure Vulnerability(APSB19-21)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Adobe Dreamweaver
  and is prone to information disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insecure protocol implementation." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to obtain sensitive information that may lead to further attacks." );
	script_tag( name: "affected", value: "Adobe Dreamweaver versions 19.0 and earlier versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Dreamweaver 19.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/dreamweaver/apsb19-21.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_dreamweaver_detect.sc" );
	script_mandatory_keys( "Adobe/Dreamweaver/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "19.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "19.1", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

