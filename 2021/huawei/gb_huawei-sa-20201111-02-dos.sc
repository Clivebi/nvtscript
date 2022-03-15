if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145190" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-19 01:39:25 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-30 13:23:00 +0000 (Mon, 30 Nov 2020)" );
	script_cve_id( "CVE-2020-1847" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Denial of Service Vulnerability in Some Huawei Products (huawei-sa-20201111-02-dos)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a denial of service vulnerability in some Huawei products." );
	script_tag( name: "insight", value: "There is no protection against the attack scenario of specific protocol. A
  remote, unauthorized attacker can construct attack scenarios, which lead to denial of service." );
	script_tag( name: "impact", value: "Successful exploit could lead to denial of service." );
	script_tag( name: "affected", value: "NIP6300 versions V500R001C30 V500R001C60

  NIP6600 versions V500R001C30 V500R001C60

  Secospace USG6300 versions V500R001C30 V500R001C60

  Secospace USG6500 versions V500R001C30 V500R001C60

  Secospace USG6600 versions V500R001C30 V500R001C60

  USG9500 versions V500R001C30 V500R001C60" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20201111-02-dos-en" );
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
version = toupper( infos["version"] );
if(IsMatchRegexp( version, "^V500R001C30" ) || IsMatchRegexp( version, "^V500R001C60" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "V500R005C00SPC200" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

