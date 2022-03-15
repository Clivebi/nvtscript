if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108801" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-18 16:49:00 +0000 (Wed, 18 Dec 2019)" );
	script_cve_id( "CVE-2019-5248" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Denial of Service Vulnerability in some Huawei Products (huawei-sa-20191204-03-dos)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Some Huawei products have DoS vulnerabilities." );
	script_tag( name: "insight", value: "Some Huawei products have DoS vulnerabilities. An attacker of a neighboring device sends a large number of specific packets. As a result, a memory leak occurs after the device uses the specific packet. As a result, the attacker can exploit this vulnerability to cause DoS attacks on the target device. (Vulnerability ID: HWPSIRT-2019-08037)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5248.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker may exploit the vulnerability to cause the target device DOS attack." );
	script_tag( name: "affected", value: "CloudEngine 12800 versions V200R001C00SPC600 V200R001C00SPC700 V200R002C01 V200R002C50SPC800 V200R002C50SPC800PWE" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-03-dos-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:cloudengine_12800_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(cpe == "cpe:/o:huawei:cloudengine_12800_firmware"){
	if(IsMatchRegexp( version, "^V200R001C00SPC700" ) || IsMatchRegexp( version, "^V200R002C50SPC800" ) || IsMatchRegexp( version, "^V200R002C50SPC800PWE" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R003C00SPC810" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R003C00SPC810" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );
