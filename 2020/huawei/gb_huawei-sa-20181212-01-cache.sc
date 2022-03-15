if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107838" );
	script_version( "2021-08-02T02:00:56+0000" );
	script_tag( name: "last_modification", value: "2021-08-02 02:00:56 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2018-0737" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Cache Timing Vulnerability in OpenSSL RSA Key Generation (huawei-sa-20181212-01-cache)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "The OpenSSL RSA Key generation algorithm has been shown to be vulnerable to a cache timing side channel attack (CVE-2018-0737)." );
	script_tag( name: "insight", value: "The OpenSSL RSA Key generation algorithm has been shown to be vulnerable to a cache timing side channel attack (CVE-2018-0737). An attacker could exploit this vulnerability to recover the private key. (Vulnerability ID: HWPSIRT-2018-06015)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability to recover the private key." );
	script_tag( name: "affected", value: "TE30 versions V600R006C10

TE40 versions V600R006C10

TE50 versions V600R006C10

TE60 versions V600R006C10" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20181212-01-cache-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:te30_firmware",
	 "cpe:/o:huawei:te40_firmware",
	 "cpe:/o:huawei:te50_firmware",
	 "cpe:/o:huawei:te60_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(IsMatchRegexp( cpe, "^cpe:/o:huawei:te(3|4|5|6)0_firmware" )){
	if(IsMatchRegexp( version, "^V600R006C10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V600R006C10SPC400" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

