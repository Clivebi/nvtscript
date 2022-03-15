if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107841" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-25 22:42:17 +0200 (Thu, 25 Jun 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-2700" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: DoS Vulnerability in Some Huawei Products (huawei-sa-20170517-01-ac)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a DoS Vulnerability in some Huawei products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to the lack of adequate input validation, the attacker can send malformed
  packets to the device, which causes the device memory leaks, leading to DoS attacks. (Vulnerability ID: HWPSIRT-2017-02118)" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to make device memory leaks, leading to DoS attacks." );
	script_tag( name: "affected", value: "AC6005 versions V200R006C10SPC200

  AC6605 versions V200R006C10SPC200." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170517-01-ac-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ac6005_firmware",
	 "cpe:/o:huawei:ac6605_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(cpe == "cpe:/o:huawei:ac6005_firmware"){
	if(IsMatchRegexp( version, "^V200R006C10SPC200" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R7C10SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:ac6605_firmware"){
	if(IsMatchRegexp( version, "^V200R006C10SPC200" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R7C10SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

