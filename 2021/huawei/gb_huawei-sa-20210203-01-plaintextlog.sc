if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145666" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-29 04:53:34 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 19:45:00 +0000 (Fri, 26 Mar 2021)" );
	script_cve_id( "CVE-2021-22310" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Information Leakage Vulnerability in Some Huawei Products (huawei-sa-20210203-01-plaintextlog)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is an information leakage vulnerability in some huawei products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to the properly storage of specific information in the log file, the
  attacker can obtain the information when a user logs in to the device. Successful exploit may cause the
  information leak." );
	script_tag( name: "impact", value: "May leading to information leakage." );
	script_tag( name: "affected", value: "NIP6300 versions V500R001C00 V500R001C20 V500R001C30

  NIP6600 versions V500R001C00 V500R001C20 V500R001C30

  Secospace USG6300 versions V500R001C00 V500R001C20 V500R001C30

  Secospace USG6500 versions V500R001C00 V500R001C20 V500R001C30

  Secospace USG6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50 V500R001C60 V500R001C80

  USG9500 versions V500R005C00 V500R005C10" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210203-01-plaintextlog-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:usg6300_firmware",
	 "cpe:/o:huawei:usg6500_firmware",
	 "cpe:/o:huawei:usg6600_firmware",
	 "cpe:/o:huawei:usg9500_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(cpe == "cpe:/o:huawei:usg6300_firmware" || cpe == "cpe:/o:huawei:usg6500_firmware"){
	if(IsMatchRegexp( version, "^V500R001C00" ) || IsMatchRegexp( version, "^V500R001C20" ) || IsMatchRegexp( version, "^V500R001C30" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:usg6600_firmware"){
	if(IsMatchRegexp( version, "^V500R001C00" ) || IsMatchRegexp( version, "^V500R001C20" ) || IsMatchRegexp( version, "^V500R001C30" ) || IsMatchRegexp( version, "^V500R001C50" ) || IsMatchRegexp( version, "^V500R001C60" ) || IsMatchRegexp( version, "^V500R001C80" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:usg9500_firmware"){
	if(IsMatchRegexp( version, "^V500R005C00" ) || IsMatchRegexp( version, "^V500R005C10" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

