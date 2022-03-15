if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107850" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-5259" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Information Leakage Vulnerability on Some Huawei Products (huawei-sa-20191211-01-vrp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is an information leakage vulnerability on some Huawei products." );
	script_tag( name: "insight", value: "There is an information leakage vulnerability on some Huawei products. An attacker with low permissions can view some high-privilege information by running specific commands.Successful exploit could cause an information disclosure condition. (Vulnerability ID: HWPSIRT-2019-04080)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5259.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Successful exploit could cause an information disclosure condition." );
	script_tag( name: "affected", value: "AR120-S versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00 V200R010C00

  AR1200 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR1200-S versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR150 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR150-S versions V200R005C00 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR160 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR200 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR200-S versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR2200 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR2200-S versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR3200 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R008C50 V200R009C00

  AR3600 versions V200R006C10 V200R007C00 V200R008C50 V200R009C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191211-01-vrp-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ar120-s_firmware",
	 "cpe:/o:huawei:ar1200_firmware",
	 "cpe:/o:huawei:ar1200-s_firmware",
	 "cpe:/o:huawei:ar150_firmware",
	 "cpe:/o:huawei:ar150-s_firmware",
	 "cpe:/o:huawei:ar160_firmware",
	 "cpe:/o:huawei:ar200_firmware",
	 "cpe:/o:huawei:ar200-s_firmware",
	 "cpe:/o:huawei:ar2200_firmware",
	 "cpe:/o:huawei:ar2200-s_firmware",
	 "cpe:/o:huawei:ar3200_firmware",
	 "cpe:/o:huawei:ar3600_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:ar120-s_firmware" ){
	if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" ) || IsMatchRegexp( version, "^V200R010C00" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if( cpe == "cpe:/o:huawei:ar1200_firmware" ){
		if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
			if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if( cpe == "cpe:/o:huawei:ar1200-s_firmware" ){
			if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
				if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
					report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
		else {
			if( cpe == "cpe:/o:huawei:ar150_firmware" ){
				if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
					if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
						report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
			else {
				if( cpe == "cpe:/o:huawei:ar150-s_firmware" ){
					if(IsMatchRegexp( version, "^V200R005C00" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
						if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
							report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
							security_message( port: 0, data: report );
							exit( 0 );
						}
					}
				}
				else {
					if( cpe == "cpe:/o:huawei:ar160_firmware" ){
						if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
							if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
								report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
								security_message( port: 0, data: report );
								exit( 0 );
							}
						}
					}
					else {
						if( cpe == "cpe:/o:huawei:ar200_firmware" ){
							if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
								if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
									report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
									security_message( port: 0, data: report );
									exit( 0 );
								}
							}
						}
						else {
							if( cpe == "cpe:/o:huawei:ar200-s_firmware" ){
								if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
									if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
										report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
										security_message( port: 0, data: report );
										exit( 0 );
									}
								}
							}
							else {
								if( cpe == "cpe:/o:huawei:ar2200_firmware" ){
									if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
										if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
											report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
											security_message( port: 0, data: report );
											exit( 0 );
										}
									}
								}
								else {
									if( cpe == "cpe:/o:huawei:ar2200-s_firmware" ){
										if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
											if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
												report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
												security_message( port: 0, data: report );
												exit( 0 );
											}
										}
									}
									else {
										if( cpe == "cpe:/o:huawei:ar3200_firmware" ){
											if(IsMatchRegexp( version, "^V200R005C20" ) || IsMatchRegexp( version, "^V200R005C32" ) || IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
												if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
													report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
													security_message( port: 0, data: report );
													exit( 0 );
												}
											}
										}
										else {
											if(cpe == "cpe:/o:huawei:ar3600_firmware"){
												if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C50" ) || IsMatchRegexp( version, "^V200R009C00" )){
													if(!patch || version_is_less( version: patch, test_version: "V200R009SPH023" )){
														report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH023" );
														security_message( port: 0, data: report );
														exit( 0 );
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
exit( 99 );

