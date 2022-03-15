if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143983" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-27 03:09:54 +0000 (Wed, 27 May 2020)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-07 15:09:00 +0000 (Wed, 07 Mar 2018)" );
	script_cve_id( "CVE-2017-17165" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: IPv6 Memory Overflow Vulnerability in Huawei Products (huawei-sa-20171213-01-ipv6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a memory overflow vulnerability in the IPv6." );
	script_tag( name: "insight", value: "There is a memory overflow vulnerability in the IPv6. An attacker can exploit this vulnerability by sending crafted malformed IPv6 packets. When the device processes the malformed IPv6 packets, a pointer offset error occurs, leading to memory overwriting and possibly causing device reset. (Vulnerability ID: HWPSIRT-2016-08018)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Attacker can exploit this vulnerability to cause device reset." );
	script_tag( name: "affected", value: "Quidway S2700 versions V200R003C00SPC300

Quidway S5300 versions V200R003C00SPC300

Quidway S5700 versions V200R003C00SPC300

S2300 versions V200R003C00 V200R003C00SPC300T V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S2700 versions V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S5300 versions V200R003C00 V200R003C00SPC300T V200R003C00SPC600 V200R003C02 V200R005C00 V200R005C01 V200R005C02 V200R005C03 V200R005C05 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S5700 versions V200R003C00 V200R003C00SPC316T V200R003C00SPC600 V200R003C02 V200R005C00 V200R005C01 V200R005C02 V200R005C03 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S600-E versions V200R008C00 V200R009C00

S6300 versions V200R003C00 V200R005C00 V200R007C00 V200R008C00 V200R009C00

S6700 versions V200R003C00 V200R005C00 V200R005C01 V200R005C02 V200R007C00 V200R008C00 V200R009C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-01-ipv6-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:quidway_s2700_firmware",
	 "cpe:/o:huawei:quidway_s5300_firmware",
	 "cpe:/o:huawei:quidway_s5700_firmware",
	 "cpe:/o:huawei:s2300_firmware",
	 "cpe:/o:huawei:s2700_firmware",
	 "cpe:/o:huawei:s5300_firmware",
	 "cpe:/o:huawei:s5700_firmware",
	 "cpe:/o:huawei:s600-e_firmware",
	 "cpe:/o:huawei:s6300_firmware",
	 "cpe:/o:huawei:s6700_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(IsMatchRegexp( cpe, "^cpe:/o:huawei:quidway_s(27|53|57)00_firmware" )){
	if(IsMatchRegexp( version, "^V200R003C00SPC300" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s2300_firmware"){
	if(IsMatchRegexp( version, "^V200R003C00" ) || IsMatchRegexp( version, "^V200R003C00SPC300T" ) || IsMatchRegexp( version, "^V200R005C00" ) || IsMatchRegexp( version, "^V200R006C00" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s2700_firmware"){
	if(IsMatchRegexp( version, "^V200R005C00" ) || IsMatchRegexp( version, "^V200R006C00" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s5300_firmware"){
	if(IsMatchRegexp( version, "^V200R003C00" ) || IsMatchRegexp( version, "^V200R003C00SPC300T" ) || IsMatchRegexp( version, "^V200R003C00SPC600" ) || IsMatchRegexp( version, "^V200R003C02" ) || IsMatchRegexp( version, "^V200R005C00" ) || IsMatchRegexp( version, "^V200R005C01" ) || IsMatchRegexp( version, "^V200R005C02" ) || IsMatchRegexp( version, "^V200R005C03" ) || IsMatchRegexp( version, "^V200R005C05" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R006C00" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s5700_firmware"){
	if(IsMatchRegexp( version, "^V200R003C00" ) || IsMatchRegexp( version, "^V200R003C00SPC316T" ) || IsMatchRegexp( version, "^V200R003C00SPC600" ) || IsMatchRegexp( version, "^V200R003C02" ) || IsMatchRegexp( version, "^V200R005C00" ) || IsMatchRegexp( version, "^V200R005C01" ) || IsMatchRegexp( version, "^V200R005C02" ) || IsMatchRegexp( version, "^V200R005C03" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R006C00" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s600-e_firmware"){
	if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s6300_firmware"){
	if(IsMatchRegexp( version, "^V200R003C00" ) || IsMatchRegexp( version, "^V200R005C00" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s6700_firmware"){
	if(IsMatchRegexp( version, "^V200R003C00" ) || IsMatchRegexp( version, "^V200R005C00" ) || IsMatchRegexp( version, "^V200R005C01" ) || IsMatchRegexp( version, "^V200R005C02" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R008C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^V200R009C00" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00SPC500" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

