CPE = "cpe:/o:huawei:usg9500_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146041" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-31 03:51:53 +0000 (Mon, 31 May 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-07 14:18:00 +0000 (Mon, 07 Jun 2021)" );
	script_cve_id( "CVE-2021-22360" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Resource Management Error Vulnerability in Some Huawei Products (huawei-sa-20210519-01-resource)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a resource management error vulnerability in some Huawei Products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An authentication attacker needs to perform specific operations
  to exploit the vulnerability on the affected device. Due to improper resource management of the
  function, the vulnerability can be exploited to cause denial of service (DoS) on affected devices." );
	script_tag( name: "impact", value: "The vulnerability can be exploited to cause a DoS on affected devices." );
	script_tag( name: "affected", value: "USG9500 versions V500R001C60SPC500 V500R005C00SPC100 V500R005C00SPC200" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210519-01-resource-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
version = toupper( version );
patch = get_kb_item( "huawei/vrp/patch" );
if(IsMatchRegexp( version, "^V500R001C60SPC500" ) || IsMatchRegexp( version, "^V500R005C00SPC100" ) || IsMatchRegexp( version, "^V500R005C00SPC200" )){
	report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

