if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112762" );
	script_version( "2021-08-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 11:01:33 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 13:51:00 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-05 18:21:00 +0000 (Wed, 05 Jun 2019)" );
	script_cve_id( "CVE-2019-5298" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Improper Authentication Vulnerability in Some Huawei AP Products (huawei-sa-20190327-01-ap)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is an improper authentication vulnerability in some Huawei AP products." );
	script_tag( name: "insight", value: "There is an improper authentication vulnerability in some Huawei AP products. Due to the improper implementation of authentication for the serial port, an attacker could exploit this vulnerability by connecting to the affected products and run a series of commands. (Vulnerability ID: HWPSIRT-2019-02007)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5298.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by connecting to the affected products and run a series of commands." );
	script_tag( name: "affected", value: "AP2000 versions V200R008C10 V200R009C00 V200R010C00

  AP4000 versions V200R008C10 V200R009C00 V200R010C00

  AP4050DN-E versions V200R009C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190327-01-ap-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ap2000_firmware",
	 "cpe:/o:huawei:ap4000_firmware",
	 "cpe:/o:huawei:ap4050dn-e_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:ap2000_firmware" ){
	if(IsMatchRegexp( version, "^V200R008C10" ) || IsMatchRegexp( version, "^V200R009C00" ) || IsMatchRegexp( version, "^V200R010C00" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R010C00SPC600" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R010C00SPC600" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if( cpe == "cpe:/o:huawei:ap4000_firmware" ){
		if(IsMatchRegexp( version, "^V200R008C10" ) || IsMatchRegexp( version, "^V200R009C00" ) || IsMatchRegexp( version, "^V200R010C00" )){
			if(!patch || version_is_less( version: patch, test_version: "V200R010C00SPC600" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R010C00SPC600" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if(cpe == "cpe:/o:huawei:ap4050dn-e_firmware"){
			if(IsMatchRegexp( version, "^V200R009C00" )){
				if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC800" )){
					report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC800" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

