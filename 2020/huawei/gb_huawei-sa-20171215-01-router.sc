if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143990" );
	script_version( "2021-08-03T03:06:28+0000" );
	script_tag( name: "last_modification", value: "2021-08-03 03:06:28 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-27 08:05:52 +0000 (Wed, 27 May 2020)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-17300" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Numeric Errors Vulnerability in Some Huawei Routers (huawei-sa-20171215-01-router)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Some Huawei routers have a numeric error vulnerability." );
	script_tag( name: "insight", value: "An unauthenticated, remote attacker may send specific TCP
  messages with keychain authentication option to the affected products. Due to the improper
  validation of the messages, it will cause numeric errors when handling the messages. Successful
  exploit will cause the affected products to reset. (Vulnerability ID: HWPSIRT-2016-08021)

  This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17300.
  Huawei has released software updates to fix this vulnerability. This advisory is available in the
  linked references." );
	script_tag( name: "impact", value: "Successful exploit will cause the affected products to reset." );
	script_tag( name: "affected", value: "S12700 versions V200R008C00 V200R009C00

S5700 versions V200R007C00 V200R008C00 V200R009C00

S6700 versions V200R008C00 V200R009C00

S7700 versions V200R008C00 V200R009C00

S9700 versions V200R008C00 V200R009C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171215-01-router-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:s12700_firmware",
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
if( cpe == "cpe:/o:huawei:s12700_firmware" ){
	if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R009C00" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if( cpe == "cpe:/o:huawei:s5700_firmware" ){
		if(IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R009C00" )){
			if(!patch || version_is_less( version: patch, test_version: "V200R007SPH010" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007SPH010" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if( cpe == "cpe:/o:huawei:s6700_firmware" ){
			if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R009C00" )){
				if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
					report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
		else {
			if( cpe == "cpe:/o:huawei:s7700_firmware" ){
				if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R009C00" )){
					if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
						report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
			else {
				if(cpe == "cpe:/o:huawei:s9700_firmware"){
					if(IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R009C00" )){
						if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
							report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
							security_message( port: 0, data: report );
							exit( 0 );
						}
					}
				}
			}
		}
	}
}
exit( 99 );

