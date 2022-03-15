if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107827" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-22 16:39:00 +0000 (Tue, 22 May 2018)" );
	script_cve_id( "CVE-2018-7920" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Improper Resource Management Vulnerability in Some Huawei Products (huawei-sa-20180418-01-ar)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is an improper resource management vulnerability in some AR series products." );
	script_tag( name: "insight", value: "There is an improper resource management vulnerability in some AR series products. Due to the improper implementation of ACL mechanism, a remote attacker may send TCP messages to the management interface of the affected device to exploit this vulnerability. Successful exploit could exhaust the socket resource of management interface, leading to a DoS condition. (Vulnerability ID: HWPSIRT-2018-03021)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2018-7920.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Successful exploit could exhaust the socket resource of management interface, leading to a DoS condition." );
	script_tag( name: "affected", value: "AR1200 versions V200R006C10SPC300

AR160 versions V200R006C10SPC300

AR200 versions V200R006C10SPC300

AR2200 versions V200R006C10SPC300

AR3200 versions V200R006C10SPC300" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180418-01-ar-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ar1200_firmware",
	 "cpe:/o:huawei:ar160_firmware",
	 "cpe:/o:huawei:ar200_firmware",
	 "cpe:/o:huawei:ar2200_firmware",
	 "cpe:/o:huawei:ar3200_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:ar1200_firmware" ){
	if(IsMatchRegexp( version, "^V200R006C10SPC300" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if( cpe == "cpe:/o:huawei:ar160_firmware" ){
		if(IsMatchRegexp( version, "^V200R006C10SPC300" )){
			if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if( cpe == "cpe:/o:huawei:ar200_firmware" ){
			if(IsMatchRegexp( version, "^V200R006C10SPC300" )){
				if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
					report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
		else {
			if( cpe == "cpe:/o:huawei:ar2200_firmware" ){
				if(IsMatchRegexp( version, "^V200R006C10SPC300" )){
					if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
						report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
			else {
				if(cpe == "cpe:/o:huawei:ar3200_firmware"){
					if(IsMatchRegexp( version, "^V200R006C10SPC300" )){
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

