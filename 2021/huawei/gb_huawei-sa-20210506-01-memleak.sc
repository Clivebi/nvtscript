if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146193" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-30 05:10:03 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 20:04:00 +0000 (Fri, 02 Jul 2021)" );
	script_cve_id( "CVE-2021-22341" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Memory Leak Vulnerability in Huawei Products (huawei-sa-20210506-01-memleak)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a memory leak vulnerability in Huawei products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A resource management weakness exists in a module. Attackers
  with high privilege can exploit this vulnerability by performing some operations. This can lead
  to memory leak." );
	script_tag( name: "impact", value: "Attackers with high privilege can exploit this vulnerability by
  performing some operations. This can lead to memory leak." );
	script_tag( name: "affected", value: "IPS Module versions V500R005C00SPC100 V500R005C00SPC200

  NGFW Module versions V500R005C00SPC100 V500R005C00SPC200

  NIP6300 versions V500R005C00SPC100 V500R005C10SPC200

  NIP6600 versions V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6300 versions V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6500 versions V500R005C00SPC100 V500R005C10SPC200

  Secospace USG6600 versions V500R005C00SPC100 V500R005C00SPC200" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210506-01-memleak-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:usg6300_firmware",
	 "cpe:/o:huawei:usg6500_firmware",
	 "cpe:/o:huawei:usg6600_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(IsMatchRegexp( cpe, "^cpe:/o:huawei:usg6[36]" )){
	if(IsMatchRegexp( version, "^V500R005C00SPC100" ) || IsMatchRegexp( version, "^V500R005C00SPC200" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:usg6500_firmware"){
	if(IsMatchRegexp( version, "^V500R005C00SPC100" ) || IsMatchRegexp( version, "^V500R005C10SPC200" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

