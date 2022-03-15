if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145665" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-29 04:45:09 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 19:55:00 +0000 (Fri, 26 Mar 2021)" );
	script_cve_id( "CVE-2021-22309" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Information Leakage Vulnerability in Huawei Products (huawei-sa-20210202-01-fw)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is insecure algorithm vulnerability in Huawei products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A module uses less random input in a secure mechanism. Attackers can
  exploit this vulnerability by brute forcing to obtain sensitive message. This can lead to information leak." );
	script_tag( name: "impact", value: "Attackers can exploit this vulnerability by brute forcing to obtain
  sensitive message. This can lead to information leak." );
	script_tag( name: "affected", value: "USG9500 versions V500R001C30SPC200 V500R001C60SPC500 V500R005C00SPC200

  USG9520 versions V500R005C00

  USG9560 versions V500R005C00

  USG9580 versions V500R005C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210202-01-fw-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:usg9500_firmware",
	 "cpe:/o:huawei:usg9520_firmware",
	 "cpe:/o:huawei:usg9560_firmware",
	 "cpe:/o:huawei:usg9580_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:usg9500_firmware" ){
	if(IsMatchRegexp( version, "^V500R001C30SPC200" ) || IsMatchRegexp( version, "^V500R001C60SPC500" ) || IsMatchRegexp( version, "^V500R005C00SPC200" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(IsMatchRegexp( version, "^V500R005C00" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

