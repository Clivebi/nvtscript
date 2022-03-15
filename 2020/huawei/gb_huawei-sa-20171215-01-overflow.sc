if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143989" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-27 07:26:27 +0000 (Wed, 27 May 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-09 14:27:00 +0000 (Fri, 09 Mar 2018)" );
	script_cve_id( "CVE-2017-17298" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Buffer Overflow Vulnerability in Some Huawei Products (huawei-sa-20171215-01-overflow)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is buffer overflow vulnerability in some Huawei products." );
	script_tag( name: "insight", value: "There is buffer overflow vulnerability in some Huawei products. An unauthenticated, remote attacker may send specially crafted certificates to the affected products. Due to insufficient validation of the certificates, successful exploit may cause buffer overflow and some service abnormal. (Vulnerability ID: HWPSIRT-2017-07013)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17298.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Successful exploit may cause buffer overflow and some service abnormal." );
	script_tag( name: "affected", value: "AR120-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR1200 versions V200R006C10 V200R006C13 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR1200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR150 versions V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR150-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR160 versions V200R006C10 V200R006C12 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR200 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20 V200R008C30

AR200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR2200 versions V200R006C10 V200R006C13 V200R006C16 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

AR2200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

AR3200 versions V200R006C10 V200R006C11 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30

AR3600 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20

AR510 versions V200R006C10 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00 V200R008C20 V200R008C30

DBS3900 TDD LTE versions V100R003C00 V100R004C10

DP300 versions V500R002C00

NetEngine16EX versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

RP200 versions V500R002C00 V600R006C00

SRG1300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

SRG2300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

SRG3300 versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

TE30 versions V100R001C02 V100R001C10 V500R002C00 V600R006C00

TE40 versions V500R002C00 V600R006C00

TE50 versions V500R002C00 V600R006C00

TE60 versions V100R001C01 V100R001C10 V500R002C00 V600R006C00

TP3106 versions V100R002C00

TP3206 versions V100R002C00 V100R002C10

ViewPoint 9030 versions V100R011C02 V100R011C03" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171215-01-overflow-en" );
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
	 "cpe:/o:huawei:dp300_firmware",
	 "cpe:/o:huawei:netengine16ex_firmware",
	 "cpe:/o:huawei:rp200_firmware",
	 "cpe:/o:huawei:srg1300_firmware",
	 "cpe:/o:huawei:srg2300_firmware",
	 "cpe:/o:huawei:srg3300_firmware",
	 "cpe:/o:huawei:te30_firmware",
	 "cpe:/o:huawei:te40_firmware",
	 "cpe:/o:huawei:te50_firmware",
	 "cpe:/o:huawei:te60_firmware",
	 "cpe:/o:huawei:tp3106_firmware",
	 "cpe:/o:huawei:tp3206_firmware",
	 "cpe:/o:huawei:viewpoint_9030_firmware" );
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
					if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
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
									if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C13" ) || IsMatchRegexp( version, "^V200R006C16" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R007C01" ) || IsMatchRegexp( version, "^V200R007C02" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
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
													if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R006C12" ) || IsMatchRegexp( version, "^V200R006C13" ) || IsMatchRegexp( version, "^V200R006C15" ) || IsMatchRegexp( version, "^V200R006C16" ) || IsMatchRegexp( version, "^V200R006C17" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
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
															if(!patch || version_is_less( version: patch, test_version: "V100R004C10SPC500" )){
																report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R004C10SPC500" );
																security_message( port: 0, data: report );
																exit( 0 );
															}
														}
													}
													else {
														if( cpe == "cpe:/o:huawei:dp300_firmware" ){
															if(IsMatchRegexp( version, "^V500R002C00" )){
																if(!patch || version_is_less( version: patch, test_version: "V500R002C00SPCb00" )){
																	report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCb00" );
																	security_message( port: 0, data: report );
																	exit( 0 );
																}
															}
														}
														else {
															if( cpe == "cpe:/o:huawei:netengine16ex_firmware" ){
																if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
																	if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
																		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
																		security_message( port: 0, data: report );
																		exit( 0 );
																	}
																}
															}
															else {
																if( cpe == "cpe:/o:huawei:rp200_firmware" ){
																	if(IsMatchRegexp( version, "^V500R002C00" ) || IsMatchRegexp( version, "^V600R006C00" )){
																		if(!patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" )){
																			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
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
																			if( cpe == "cpe:/o:huawei:srg3300_firmware" ){
																				if(IsMatchRegexp( version, "^V200R006C10" ) || IsMatchRegexp( version, "^V200R007C00" ) || IsMatchRegexp( version, "^V200R008C20" ) || IsMatchRegexp( version, "^V200R008C30" )){
																					if(!patch || version_is_less( version: patch, test_version: "V200R009C00" )){
																						report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
																						security_message( port: 0, data: report );
																						exit( 0 );
																					}
																				}
																			}
																			else {
																				if( cpe == "cpe:/o:huawei:te30_firmware" ){
																					if(IsMatchRegexp( version, "^V100R001C02" ) || IsMatchRegexp( version, "^V100R001C10" ) || IsMatchRegexp( version, "^V500R002C00" ) || IsMatchRegexp( version, "^V600R006C00" )){
																						if(!patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" )){
																							report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
																							security_message( port: 0, data: report );
																							exit( 0 );
																						}
																					}
																				}
																				else {
																					if( cpe == "cpe:/o:huawei:te40_firmware" ){
																						if(IsMatchRegexp( version, "^V500R002C00" ) || IsMatchRegexp( version, "^V600R006C00" )){
																							if(!patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" )){
																								report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
																								security_message( port: 0, data: report );
																								exit( 0 );
																							}
																						}
																					}
																					else {
																						if( cpe == "cpe:/o:huawei:te50_firmware" ){
																							if(IsMatchRegexp( version, "^V500R002C00" ) || IsMatchRegexp( version, "^V600R006C00" )){
																								if(!patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" )){
																									report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
																									security_message( port: 0, data: report );
																									exit( 0 );
																								}
																							}
																						}
																						else {
																							if( cpe == "cpe:/o:huawei:te60_firmware" ){
																								if(IsMatchRegexp( version, "^V100R001C01" ) || IsMatchRegexp( version, "^V100R001C10" ) || IsMatchRegexp( version, "^V500R002C00" ) || IsMatchRegexp( version, "^V600R006C00" )){
																									if(!patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" )){
																										report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
																										security_message( port: 0, data: report );
																										exit( 0 );
																									}
																								}
																							}
																							else {
																								if( cpe == "cpe:/o:huawei:tp3106_firmware" ){
																									if(IsMatchRegexp( version, "^V100R002C00" )){
																										if(!patch || version_is_less( version: patch, test_version: "V100R002C00SPC800" )){
																											report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800" );
																											security_message( port: 0, data: report );
																											exit( 0 );
																										}
																									}
																								}
																								else {
																									if( cpe == "cpe:/o:huawei:tp3206_firmware" ){
																										if(IsMatchRegexp( version, "^V100R002C00" ) || IsMatchRegexp( version, "^V100R002C10" )){
																											if(!patch || version_is_less( version: patch, test_version: "V100R002C00SPC800" )){
																												report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800" );
																												security_message( port: 0, data: report );
																												exit( 0 );
																											}
																										}
																									}
																									else {
																										if(cpe == "cpe:/o:huawei:viewpoint_9030_firmware"){
																											if(IsMatchRegexp( version, "^V100R011C02" ) || IsMatchRegexp( version, "^V100R011C03" )){
																												if(!patch || version_is_less( version: patch, test_version: "V100R011C03SPC800" )){
																													report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R011C03SPC800" );
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

