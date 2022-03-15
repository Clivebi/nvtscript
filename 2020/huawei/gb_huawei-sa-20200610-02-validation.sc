if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144122" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-17 05:58:51 +0000 (Wed, 17 Jun 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-18 19:38:00 +0000 (Thu, 18 Jun 2020)" );
	script_cve_id( "CVE-2020-9075" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Products Insufficient Input Verification (huawei-sa-20200610-02-validation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Multiple Huawei products are prone to an insufficient input verification
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker with limited privilege can exploit this vulnerability to
  access a specific directory. Successful exploitation of this vulnerability may lead to information leakage." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability may lead to information leakage." );
	script_tag( name: "affected", value: "Huawei Secospace USG6300 and USG6300E." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200610-02-validation-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:usg6300_firmware",
	 "cpe:/o:huawei:usg6300e_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
if(cpe == "cpe:/o:huawei:usg6300_firmware"){
	if(version == "V500R001C30" || version == "V500R001C50" || version == "V500R001C60" || version == "V500R001C80" || version == "V500R005C00" || version == "V500R005C10"){
		report = report_fixed_ver( installed_version: version, fixed_version: "V500R005C20SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:usg6300e_firmware"){
	if(version == "V600R006C00"){
		report = report_fixed_ver( installed_version: version, fixed_version: "V600R007C00SPC200" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

