if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146194" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-30 05:22:01 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-07 11:34:00 +0000 (Wed, 07 Jul 2021)" );
	script_cve_id( "CVE-2021-22329" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Improper Licenses Management Vulnerability in Some Products (huawei-sa-20210407-01-resourcemanagement)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There has a license management vulnerability in some huawei products." );
	script_tag( name: "insight", value: "An attacker with high privilege needs to perform specific
  operations to exploit the vulnerability on the affected device. Due to improper license
  management of the device, as a result, the license file can be applied and affect integrity of
  the device." );
	script_tag( name: "impact", value: "The vulnerability can be exploited to affect the integrity of
  the device." );
	script_tag( name: "affected", value: "S12700 versions V200R007C01 V200R007C01B102 V200R008C00
  V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S1700 versions V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S2700 versions V200R008C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S5700 versions V200R008C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10 V200R011C10SPC100

  S6700 versions V200R008C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10 V200R011C10SPC100

  S7700 versions V200R008C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S9700 versions V200R007C01 V200R007C01B102 V200R008C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100
  V200R011C10" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210407-01-resourcemanagement-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:s12700_firmware",
	 "cpe:/o:huawei:s1700_firmware",
	 "cpe:/o:huawei:s2700_firmware",
	 "cpe:/o:huawei:s5700_firmware",
	 "cpe:/o:huawei:s6700_firmware",
	 "cpe:/o:huawei:s7700_firmware",
	 "cpe:/o:huawei:s9700_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(cpe == "cpe:/o:huawei:s12700_firmware"){
	if(IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C01B102" ) || IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R010C00SPC300" ) || IsMatchRegexp( version, "^V200R011C00" ) || IsMatchRegexp( version, "^V200R011C00SPC100" ) || IsMatchRegexp( version, "^V200R011C10" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R020C00SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s1700_firmware"){
	if(IsMatchRegexp( version, "^V200R010C00SPC300" ) || IsMatchRegexp( version, "^V200R011C00" ) || IsMatchRegexp( version, "^V200R011C00SPC100" ) || IsMatchRegexp( version, "^V200R011C10" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R020C00SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s2700_firmware" || cpe == "cpe:/o:huawei:s7700_firmware"){
	if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R010C00SPC300" ) || IsMatchRegexp( version, "^V200R011C00" ) || IsMatchRegexp( version, "^V200R011C00SPC100" ) || IsMatchRegexp( version, "^V200R011C10" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R020C00SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s5700_firmware" || cpe == "cpe:/o:huawei:s6700_firmware"){
	if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R010C00SPC300" ) || IsMatchRegexp( version, "^V200R011C00" ) || IsMatchRegexp( version, "^V200R011C00SPC100" ) || IsMatchRegexp( version, "^V200R011C10" ) || IsMatchRegexp( version, "^V200R011C10SPC100" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R020C00SPC300" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:huawei:s9700_firmware"){
	if(IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C01B102" ) || IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R010C00SPC300" ) || IsMatchRegexp( version, "^V200R011C00" ) || IsMatchRegexp( version, "^V200R011C00SPC100" ) || IsMatchRegexp( version, "^V200R011C10" )){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R013SPH015" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

