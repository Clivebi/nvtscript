CPE = "cpe:/o:huawei:cloudengine_12800_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143944" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-20 04:30:31 +0000 (Wed, 20 May 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-26 16:01:00 +0000 (Mon, 26 Mar 2018)" );
	script_cve_id( "CVE-2016-8782" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Memory Leak Vulnerability in Some Huawei Products (huawei-sa-20161214-01-ldp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Some Huawei products have a memory leak vulnerability." );
	script_tag( name: "insight", value: "Some Huawei products have a memory leak vulnerability. An unauthenticated attacker may send specific Label Distribution Protocol (LDP) packets to the devices. Due to improper validation of some specific fields of the packet, the LDP processing module repeatedly applies for memory, resulting in memory leak. (Vulnerability ID: HWPSIRT-2016-08013)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to cause memory leak." );
	script_tag( name: "affected", value: "CloudEngine 12800 versions V100R003C00SPC600 V100R003C10 V100R005C00 V100R005C10 V100R006C00SPC600" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161214-01-ldp-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
version = toupper( version );
if(IsMatchRegexp( version, "^V100R003C00" ) || IsMatchRegexp( version, "^V100R003C10" ) || IsMatchRegexp( version, "^V100R005C00" ) || IsMatchRegexp( version, "^V100R005C10" ) || IsMatchRegexp( version, "^V100R006C00" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "V200R001C00SPC700" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

