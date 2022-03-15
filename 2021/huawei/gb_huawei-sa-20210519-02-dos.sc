if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146040" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-31 03:42:58 +0000 (Mon, 31 May 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-04 19:34:00 +0000 (Fri, 04 Jun 2021)" );
	script_cve_id( "CVE-2021-22359" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Denial of Service Vulnerability in Some Huawei Products (huawei-sa-20210519-02-dos)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a denial of service (DoS) vulnerability in some Huawei products." );
	script_tag( name: "insight", value: "An attacker could exploit this vulnerability by sending specific
  message to a targeted device. Due to insufficient input validation, successful exploit can cause
  the service abnormal." );
	script_tag( name: "impact", value: "Successful exploit can cause a DoS." );
	script_tag( name: "affected", value: "S5700 versions V200R005C00SPC500

  S6700 versions V200R005C00SPC500" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210519-02-dos-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:s5700_firmware",
	 "cpe:/o:huawei:s6700_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(IsMatchRegexp( version, "^V200R005C00SPC500" )){
	report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005SPH026" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

