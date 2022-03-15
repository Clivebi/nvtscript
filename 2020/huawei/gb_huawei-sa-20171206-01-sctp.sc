if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143980" );
	script_version( "2021-08-04T11:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 11:01:00 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 08:56:16 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-12 20:18:00 +0000 (Fri, 12 Jan 2018)" );
	script_cve_id( "CVE-2017-15317" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Input Validation Vulnerability in Multiple Huawei Products (huawei-sa-20171206-01-sctp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is an input validation vulnerability in Huawei multiple products." );
	script_tag( name: "insight", value: "There is an input validation vulnerability in Huawei multiple products. Due to the insufficient input validation, an attacker may craft a malformed packet and send it to the device, causing the device to read out of bounds and restart. (Vulnerability ID: HWPSIRT-2017-01017)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15317.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to make the device read out of bounds and restart." );
	script_tag( name: "affected", value: "AR120-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR1200 versions V200R006C10 V200R006C13 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR1200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR150 versions V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR150-S versions V200R006C10SPC300 V200R007C00 V200R008C20 V200R008C30

AR160 versions V200R006C10 V200R006C12 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR200 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20 V200R008C30

AR200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR2200 versions V200R006C10 V200R006C13 V200R006C16PWE V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR2200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR3200 versions V200R006C10 V200R006C11 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30

AR3600 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20

AR510 versions V200R006C10 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00SPC600 V200R008C20 V200R008C30

DBS3900 TDD LTE versions V100R003C00 V100R004C10

SRG1300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

SRG2300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

SRG3300 versions V200R006C10 V200R007C00 V200R008C20 V200R008C30" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-sctp-en" );
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
	 "cpe:/o:huawei:ar3600_firmware",
	 "cpe:/o:huawei:ar510_firmware",
	 "cpe:/o:huawei:dbs3900_tdd_lte_firmware",
	 "cpe:/o:huawei:srg1300_firmware",
	 "cpe:/o:huawei:srg2300_firmware",
	 "cpe:/o:huawei:srg3300_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:ar120-s_firmware" ){
	if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if( cpe == "cpe:/o:huawei:ar1200_firmware" ){
		if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C13" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
			if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if( cpe == "cpe:/o:huawei:ar1200-s_firmware" ){
			if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
				if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
					report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
		else {
			if( cpe == "cpe:/o:huawei:ar150_firmware" ){
				if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
					if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
						report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
			else {
				if( cpe == "cpe:/o:huawei:ar150-s_firmware" ){
					if(IsMatchRegexp( version, "^V200R006C10SPC300" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
						if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
							report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
							security_message( port: 0, data: report );
							exit( 0 );
						}
					}
				}
				else {
					if( cpe == "cpe:/o:huawei:ar160_firmware" ){
						if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C12" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
							if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
								report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
								security_message( port: 0, data: report );
								exit( 0 );
							}
						}
					}
					else {
						if( cpe == "cpe:/o:huawei:ar200_firmware" ){
							if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
								if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
									report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
									security_message( port: 0, data: report );
									exit( 0 );
								}
							}
						}
						else {
							if( cpe == "cpe:/o:huawei:ar200-s_firmware" ){
								if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
									if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
										report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
										security_message( port: 0, data: report );
										exit( 0 );
									}
								}
							}
							else {
								if( cpe == "cpe:/o:huawei:ar2200_firmware" ){
									if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C13" ) || IsMatchRegexp( version, "^V200R006C16PWE" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
										if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
											report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
											security_message( port: 0, data: report );
											exit( 0 );
										}
									}
								}
								else {
									if( cpe == "cpe:/o:huawei:ar2200-s_firmware" ){
										if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
											if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
												report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
												security_message( port: 0, data: report );
												exit( 0 );
											}
										}
									}
									else {
										if( cpe == "cpe:/o:huawei:ar3200_firmware" ){
											if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C11" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C00" ) || IsMatchRegexp( version, "^V200R008C10" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
												if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
													report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
													security_message( port: 0, data: report );
													exit( 0 );
												}
											}
										}
										else {
											if( cpe == "cpe:/o:huawei:ar3600_firmware" ){
												if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R008C20" )){
													if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
														report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
														security_message( port: 0, data: report );
														exit( 0 );
													}
												}
											}
											else {
												if( cpe == "cpe:/o:huawei:ar510_firmware" ){
													if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C12" ) || IsMatchRegexp( version, "^V200R006C13" ) || IsMatchRegexp( version, "^V200R006C15" ) || IsMatchRegexp( version, "^V200R006C16" ) || IsMatchRegexp( version, "^V200R006C17" ) || IsMatchRegexp( version, "^V200R007C00SPC600" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
														if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
															report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
															security_message( port: 0, data: report );
															exit( 0 );
														}
													}
												}
												else {
													if( cpe == "cpe:/o:huawei:dbs3900_tdd_lte_firmware" ){
														if(IsMatchRegexp( version, "^V100R003C00" ) || IsMatchRegexp( version, "^V100R004C10" )){
															if(!patch || version_is_less( version: patch, test_version: "V100R004C10SPC400" )){
																report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R004C10SPC400" );
																security_message( port: 0, data: report );
																exit( 0 );
															}
														}
													}
													else {
														if( cpe == "cpe:/o:huawei:srg1300_firmware" ){
															if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
																if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
																	report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
																	security_message( port: 0, data: report );
																	exit( 0 );
																}
															}
														}
														else {
															if( cpe == "cpe:/o:huawei:srg2300_firmware" ){
																if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
																	if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
																		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
																		security_message( port: 0, data: report );
																		exit( 0 );
																	}
																}
															}
															else {
																if(cpe == "cpe:/o:huawei:srg3300_firmware"){
																	if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
																		if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
																			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
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
				}
			}
		}
	}
}
exit( 99 );

