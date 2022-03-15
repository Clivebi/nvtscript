CPE = "cpe:/o:huawei:usg6600_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143982" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 09:18:15 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-26 15:20:00 +0000 (Mon, 26 Feb 2018)" );
	script_cve_id( "CVE-2017-17163" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Out-of-Bounds Memory Access Vulnerability on Some Huawei FireWall Products (huawei-sa-20171213-01-firewall)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is an Out-of-Bounds memory access vulnerability in Huawei FireWall products due to insufficient verification." );
	script_tag( name: "insight", value: "There is an Out-of-Bounds memory access vulnerability in Huawei FireWall products due to insufficient verification. An authenticated local attacker can make processing crash by executing some commands. The attacker can exploit this vulnerability to cause a denial of service. (Vulnerability ID: HWPSIRT-2017-06146)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17163.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "The attacker can exploit these vulnerabilities to cause a denial of service." );
	script_tag( name: "affected", value: "Secospace USG6600 versions V500R001C30SPC100" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-01-firewall-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
version = toupper( version );
patch = get_kb_item( "huawei/vrp/patch" );
if(IsMatchRegexp( version, "^V500R001C30SPC100" )){
	report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC300", fixed_patch: "V500R001SPH012" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

