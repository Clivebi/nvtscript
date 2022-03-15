if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142864" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-09-09 06:53:34 +0000 (Mon, 09 Sep 2019)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-03 14:38:00 +0000 (Tue, 03 Sep 2019)" );
	script_cve_id( "CVE-2019-9931" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Lexmark Printer SNMP DoS Vulnerability (TE919)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_lexmark_printer_consolidation.sc" );
	script_mandatory_keys( "lexmark_printer/detected", "lexmark_printer/model" );
	script_tag( name: "summary", value: "Some Lexmark printers contain a denial of service vulnerability in their SNMP
  service. This vulnerability can be exploited to crash the device." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable firmware version is present on the target host." );
	script_tag( name: "insight", value: "A specially crafted request to the SNMP service will cause a vulnerable device
  to crash. If the 'General Settings'->Error Recovery' setting is set to 'Auto Reboot' (the default) then the
  device will automatically reboot until the 'Max Auto Reboots' limit is reached." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability can lead to a denial of service
  on the affected device by causing it to crash." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "http://support.lexmark.com/index?page=content&id=TE919" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "lexmark_printer/model" )){
	exit( 0 );
}
cpe = "cpe:/o:lexmark:" + tolower( model ) + "_firmware";
if(!version = get_app_version( cpe: cpe, nofork: TRUE )){
	exit( 0 );
}
if( IsMatchRegexp( model, "^CS31" ) ){
	if(version_is_less( version: version, test_version: "lw71.vyl.p231" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "lw71.vyl.p231" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if( IsMatchRegexp( model, "^CS41" ) ){
		if(version_is_less( version: version, test_version: "lw71.vy2.p231" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "lw71.vy2.p231" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
	else {
		if( IsMatchRegexp( model, "^CS51" ) ){
			if(version_is_less( version: version, test_version: "lw71.vy4.p231" )){
				report = report_fixed_ver( installed_version: version, fixed_version: "lw71.vy4.p231" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
		else {
			if( IsMatchRegexp( model, "^CX310" ) ){
				if(version_is_less( version: version, test_version: "lw71.gm2.p231" )){
					report = report_fixed_ver( installed_version: version, fixed_version: "lw71.gm2.p231" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
			else {
				if( IsMatchRegexp( model, "^(CX410|C2130)" ) ){
					if(version_is_less( version: version, test_version: "lw71.gm4.p231" )){
						report = report_fixed_ver( installed_version: version, fixed_version: "lw71.gm4.p231" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
				else {
					if( IsMatchRegexp( model, "^(CX510|C2132)" ) ){
						if(version_is_less( version: version, test_version: "lw71.gm7.p231" )){
							report = report_fixed_ver( installed_version: version, fixed_version: "lw71.gm7.p231" );
							security_message( port: 0, data: report );
							exit( 0 );
						}
					}
					else {
						if( IsMatchRegexp( model, "^(MS31[027]|MS410|M1140)" ) ){
							if(version_is_less( version: version, test_version: "lw71.prl.p231" )){
								report = report_fixed_ver( installed_version: version, fixed_version: "lw71.prl.p231" );
								security_message( port: 0, data: report );
								exit( 0 );
							}
						}
						else {
							if( IsMatchRegexp( model, "^(MS315|MS41[57])" ) ){
								if(version_is_less( version: version, test_version: "lw71.tl2.p231" )){
									report = report_fixed_ver( installed_version: version, fixed_version: "lw71.tl2.p231" );
									security_message( port: 0, data: report );
									exit( 0 );
								}
							}
							else {
								if( IsMatchRegexp( model, "^(MS51|MS610dn|MS617)" ) ){
									if(version_is_less( version: version, test_version: "lw71.pr2.p231" )){
										report = report_fixed_ver( installed_version: version, fixed_version: "lw71.pr2.p231" );
										security_message( port: 0, data: report );
										exit( 0 );
									}
								}
								else {
									if( IsMatchRegexp( model, "^(M1145|M3150dn)" ) ){
										if(version_is_less( version: version, test_version: "lw71.pr2.p231" )){
											report = report_fixed_ver( installed_version: version, fixed_version: "lw71.pr2.p231" );
											security_message( port: 0, data: report );
											exit( 0 );
										}
									}
									else {
										if( IsMatchRegexp( model, "^(MS610de|M3150)" ) ){
											if(version_is_less( version: version, test_version: "lw71.pr4.p231" )){
												report = report_fixed_ver( installed_version: version, fixed_version: "lw71.pr4.p231" );
												security_message( port: 0, data: report );
												exit( 0 );
											}
										}
										else {
											if( IsMatchRegexp( model, "^(MS71|M5163dn|MS81[01278])" ) ){
												if(version_is_less( version: version, test_version: "lw71.dn2.p231" )){
													report = report_fixed_ver( installed_version: version, fixed_version: "lw71.dn2.p231" );
													security_message( port: 0, data: report );
													exit( 0 );
												}
											}
											else {
												if( IsMatchRegexp( model, "^(MS810de|M5155|MS5163)" ) ){
													if(version_is_less( version: version, test_version: "lw71.dn4.p231" )){
														report = report_fixed_ver( installed_version: version, fixed_version: "lw71.dn4.p231" );
														security_message( port: 0, data: report );
														exit( 0 );
													}
												}
												else {
													if( IsMatchRegexp( model, "^(MS812de|M5170)" ) ){
														if(version_is_less( version: version, test_version: "lw71.dn7.p231" )){
															report = report_fixed_ver( installed_version: version, fixed_version: "lw71.dn7.p231" );
															security_message( port: 0, data: report );
															exit( 0 );
														}
													}
													else {
														if( IsMatchRegexp( model, "^MS91" ) ){
															if(version_is_less( version: version, test_version: "lw71.sa.p231" )){
																report = report_fixed_ver( installed_version: version, fixed_version: "lw71.sa.p231" );
																security_message( port: 0, data: report );
																exit( 0 );
															}
														}
														else {
															if( IsMatchRegexp( model, "^(MX31|XM1135)" ) ){
																if(version_is_less( version: version, test_version: "lw71.sb2.p231" )){
																	report = report_fixed_ver( installed_version: version, fixed_version: "lw71.sb2.p231" );
																	security_message( port: 0, data: report );
																	exit( 0 );
																}
															}
															else {
																if( IsMatchRegexp( model, "^(MX410|MX51[01]|XM114[05])" ) ){
																	if(version_is_less( version: version, test_version: "lw71.sb4.p231" )){
																		report = report_fixed_ver( installed_version: version, fixed_version: "lw71.sb4.p231" );
																		security_message( port: 0, data: report );
																		exit( 0 );
																	}
																}
																else {
																	if( IsMatchRegexp( model, "^(MX61[01]|XM3150)" ) ){
																		if(version_is_less( version: version, test_version: "lw71.sb7.p231" )){
																			report = report_fixed_ver( installed_version: version, fixed_version: "lw71.sb7.p231" );
																			security_message( port: 0, data: report );
																			exit( 0 );
																		}
																	}
																	else {
																		if( IsMatchRegexp( model, "^(MX[78]1|XM51|XM71)" ) ){
																			if(version_is_less( version: version, test_version: "lw71.tu.p231" )){
																				report = report_fixed_ver( installed_version: version, fixed_version: "lw71.tu.p231" );
																				security_message( port: 0, data: report );
																				exit( 0 );
																			}
																		}
																		else {
																			if( IsMatchRegexp( model, "^(MX91|XM91)" ) ){
																				if(version_is_less( version: version, test_version: "lw71.mg.p231" )){
																					report = report_fixed_ver( installed_version: version, fixed_version: "lw71.mg.p231" );
																					security_message( port: 0, data: report );
																					exit( 0 );
																				}
																			}
																			else {
																				if( IsMatchRegexp( model, "^MX6500e" ) ){
																					if(version_is_less( version: version, test_version: "lw71.jd.p231" )){
																						report = report_fixed_ver( installed_version: version, fixed_version: "lw71.jd.p231" );
																						security_message( port: 0, data: report );
																						exit( 0 );
																					}
																				}
																				else {
																					if( IsMatchRegexp( model, "^C746" ) ){
																						if(version_is_less( version: version, test_version: "lhs60.cm2.p698" )){
																							report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.cm2.p698" );
																							security_message( port: 0, data: report );
																							exit( 0 );
																						}
																					}
																					else {
																						if( IsMatchRegexp( model, "^C(S)?748" ) ){
																							if(version_is_less( version: version, test_version: "lhs60.cm4.p698" )){
																								report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.cm4.p698" );
																								security_message( port: 0, data: report );
																								exit( 0 );
																							}
																						}
																						else {
																							if( IsMatchRegexp( model, "^(C792|CS796)" ) ){
																								if(version_is_less( version: version, test_version: "lhs60.hc.p698" )){
																									report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.hc.p698" );
																									security_message( port: 0, data: report );
																									exit( 0 );
																								}
																							}
																							else {
																								if( IsMatchRegexp( model, "^C925" ) ){
																									if(version_is_less( version: version, test_version: "lhs60.hv.p698" )){
																										report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.hv.p698" );
																										security_message( port: 0, data: report );
																										exit( 0 );
																									}
																								}
																								else {
																									if( IsMatchRegexp( model, "^C950" ) ){
																										if(version_is_less( version: version, test_version: "lhs60.tp.p698" )){
																											report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.tp.p698" );
																											security_message( port: 0, data: report );
																											exit( 0 );
																										}
																									}
																									else {
																										if( IsMatchRegexp( model, "^X(S)?548" ) ){
																											if(version_is_less( version: version, test_version: "lhs60.vk.p698" )){
																												report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.vk.p698" );
																												security_message( port: 0, data: report );
																												exit( 0 );
																											}
																										}
																										else {
																											if( IsMatchRegexp( model, "^(X74|XS748)" ) ){
																												if(version_is_less( version: version, test_version: "lhs60.ny.p698" )){
																													report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.ny.p698" );
																													security_message( port: 0, data: report );
																													exit( 0 );
																												}
																											}
																											else {
																												if( IsMatchRegexp( model, "^(X792|XS79)" ) ){
																													if(version_is_less( version: version, test_version: "lhs60.mr.p698" )){
																														report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.mr.p698" );
																														security_message( port: 0, data: report );
																														exit( 0 );
																													}
																												}
																												else {
																													if( IsMatchRegexp( model, "^X(S)?925" ) ){
																														if(version_is_less( version: version, test_version: "lhs60.hk.p698" )){
																															report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.hk.p698" );
																															security_message( port: 0, data: report );
																															exit( 0 );
																														}
																													}
																													else {
																														if( IsMatchRegexp( model, "^X(S)?95" ) ){
																															if(version_is_less( version: version, test_version: "lhs60.tq.p698" )){
																																report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.tq.p698" );
																																security_message( port: 0, data: report );
																																exit( 0 );
																															}
																														}
																														else {
																															if( IsMatchRegexp( model, "^6500e" ) ){
																																if(version_is_less( version: version, test_version: "lhs60.jr.p698" )){
																																	report = report_fixed_ver( installed_version: version, fixed_version: "lhs60.jr.p698" );
																																	security_message( port: 0, data: report );
																																	exit( 0 );
																																}
																															}
																															else {
																																if( IsMatchRegexp( model, "^C734" ) ){
																																	if(version_is_less( version: version, test_version: "lr.sk.p815" )){
																																		report = report_fixed_ver( installed_version: version, fixed_version: "lr.sk.p815" );
																																		security_message( port: 0, data: report );
																																		exit( 0 );
																																	}
																																}
																																else {
																																	if( IsMatchRegexp( model, "^C736" ) ){
																																		if(version_is_less( version: version, test_version: "lr.ske.p815" )){
																																			report = report_fixed_ver( installed_version: version, fixed_version: "lr.ske.p815" );
																																			security_message( port: 0, data: report );
																																			exit( 0 );
																																		}
																																	}
																																	else {
																																		if( IsMatchRegexp( model, "^E46" ) ){
																																			if(version_is_less( version: version, test_version: "lr.lbh.p815" )){
																																				report = report_fixed_ver( installed_version: version, fixed_version: "lr.lbh.p815" );
																																				security_message( port: 0, data: report );
																																				exit( 0 );
																																			}
																																		}
																																		else {
																																			if( IsMatchRegexp( model, "^T65" ) ){
																																				if(version_is_less( version: version, test_version: "lr.jb.p815" )){
																																					report = report_fixed_ver( installed_version: version, fixed_version: "lr.jb.p815" );
																																					security_message( port: 0, data: report );
																																					exit( 0 );
																																				}
																																			}
																																			else {
																																				if( IsMatchRegexp( model, "^X46" ) ){
																																					if(version_is_less( version: version, test_version: "lr.bs.p815" )){
																																						report = report_fixed_ver( installed_version: version, fixed_version: "lr.bs.p815" );
																																						security_message( port: 0, data: report );
																																						exit( 0 );
																																					}
																																				}
																																				else {
																																					if( IsMatchRegexp( model, "^X65" ) ){
																																						if(version_is_less( version: version, test_version: "lr.mn.p815" )){
																																							report = report_fixed_ver( installed_version: version, fixed_version: "lr.mn.p815" );
																																							security_message( port: 0, data: report );
																																							exit( 0 );
																																						}
																																					}
																																					else {
																																						if( IsMatchRegexp( model, "^X73" ) ){
																																							if(version_is_less( version: version, test_version: "lr.fl.p815" )){
																																								report = report_fixed_ver( installed_version: version, fixed_version: "lr.fl.p815" );
																																								security_message( port: 0, data: report );
																																								exit( 0 );
																																							}
																																						}
																																						else {
																																							if( IsMatchRegexp( model, "^W850" ) ){
																																								if(version_is_less( version: version, test_version: "lr.jb.p815" )){
																																									report = report_fixed_ver( installed_version: version, fixed_version: "lr.jb.p815" );
																																									security_message( port: 0, data: report );
																																									exit( 0 );
																																								}
																																							}
																																							else {
																																								if(IsMatchRegexp( model, "^X86" )){
																																									if(version_is_less( version: version, test_version: "lr.sp.p815" )){
																																										report = report_fixed_ver( installed_version: version, fixed_version: "lr.sp.p815" );
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

