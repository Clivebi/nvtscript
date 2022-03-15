if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108590" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-06-01 07:09:18 +0000 (Sat, 01 Jun 2019)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (NTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "ntp_open.sc" );
	script_mandatory_keys( "ntp/system_banner/available" );
	script_tag( name: "summary", value: "NTP server based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (NTP)";
BANNER_TYPE = "NTP Server banner";
port = service_get_port( default: 123, ipproto: "udp", proto: "ntp" );
if(!banner = get_kb_item( "ntp/" + port + "/system_banner" )){
	exit( 0 );
}
if(banner == "/"){
	exit( 0 );
}
banner_lo = tolower( banner );
if( ContainsString( banner_lo, "linux" ) ){
	if( ContainsString( banner, "-gentoo" ) ){
		os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		if( ContainsString( banner_lo, "-arch" ) ){
			os_register_and_report( os: "Arch Linux", cpe: "cpe:/o:archlinux:arch_linux", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( banner_lo, "-amazon" ) ){
				os_register_and_report( os: "Amazon Linux", cpe: "cpe:/o:amazon:linux", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				version = eregmatch( pattern: "Linux/?([0-9.]+)", string: banner );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Linux", version: version[1], cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
			}
		}
	}
}
else {
	if( ContainsString( banner_lo, "windows" ) || IsMatchRegexp( banner, "^win" ) ){
		if( IsMatchRegexp( banner, "win2008r2" ) ){
			os_register_and_report( os: "Microsoft Windows Server 2008 R2", cpe: "cpe:/o:microsoft:windows_server_2008:r2", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
		}
		else {
			if( IsMatchRegexp( banner, "win2008" ) ){
				os_register_and_report( os: "Microsoft Windows Server 2008", cpe: "cpe:/o:microsoft:windows_server_2008", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
			}
			else {
				if( IsMatchRegexp( banner, "win2016" ) ){
					os_register_and_report( os: "Microsoft Windows Server 2016", cpe: "cpe:/o:microsoft:windows_server_2016", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
				}
				else {
					if( IsMatchRegexp( banner, "win2012r2" ) ){
						os_register_and_report( os: "Microsoft Windows Server 2012 R2", cpe: "cpe:/o:microsoft:windows_server_2012:r2", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
					}
					else {
						if( IsMatchRegexp( banner, "win2012" ) ){
							os_register_and_report( os: "Microsoft Windows Server 2012", cpe: "cpe:/o:microsoft:windows_server_2012", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
						}
						else {
							if( IsMatchRegexp( banner, "win2003" ) ){
								os_register_and_report( os: "Microsoft Windows Server 2003", cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
							}
							else {
								os_register_and_report( os: banner, cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "windows" );
							}
						}
					}
				}
			}
		}
	}
	else {
		if( ContainsString( banner_lo, "unix" ) ){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( banner_lo, "freebsd" ) ){
				version = eregmatch( pattern: "FreeBSD(/|JNPR-)([0-9.]+)(-RELEASE-(p[0-9]+))?", string: banner );
				if( !isnull( version[2] ) && !isnull( version[4] ) ){
					os_register_and_report( os: "FreeBSD", version: version[2], patch: version[4], cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( !isnull( version[2] ) ){
						os_register_and_report( os: "FreeBSD", version: version[2], cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
				}
			}
			else {
				if( ContainsString( banner_lo, "netbsd" ) ){
					version = eregmatch( pattern: "NetBSD/([0-9.]+)", string: banner );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "NetBSD", version: version[1], cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
				}
				else {
					if( ContainsString( banner_lo, "openbsd" ) ){
						version = eregmatch( pattern: "OpenBSD/([0-9.]+)", string: banner );
						if( !isnull( version[1] ) ){
							os_register_and_report( os: "OpenBSD", version: version[1], cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
					}
					else {
						if( ContainsString( banner_lo, "sunos" ) ){
							version = eregmatch( pattern: "SunOS/([0-9.]+)", string: banner );
							if( !isnull( version[1] ) ){
								os_register_and_report( os: "SunOS", version: version[1], cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
						}
						else {
							if( ContainsString( banner_lo, "hp-ux" ) ){
								version = eregmatch( pattern: "HP-UX/([0-9.]+)", string: banner );
								if( !isnull( version[1] ) ){
									os_register_and_report( os: "HP-UX", version: version[1], cpe: "cpe:/o:hp:hp-ux", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									os_register_and_report( os: "HP-UX", cpe: "cpe:/o:hp:hp-ux", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
							}
							else {
								if( ContainsString( banner_lo, "data ontap" ) ){
									version = eregmatch( pattern: "Data ONTAP/([0-9.a-zA-Z\\-]+)", string: banner );
									if( !isnull( version[1] ) ){
										os_register_and_report( os: "NetApp Data ONTAP", version: version[1], cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
								}
								else {
									if( ContainsString( banner_lo, "junos" ) ){
										version = eregmatch( pattern: "JUNOS([0-9.a-zA-Z]+)", string: banner );
										if( !isnull( version[1] ) ){
											os_register_and_report( os: "JunOS", version: version[1], cpe: "cpe:/o:juniper:junos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											os_register_and_report( os: "JunOS", cpe: "cpe:/o:juniper:junos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
									}
									else {
										if( ContainsString( banner_lo, "secureos" ) ){
											version = eregmatch( pattern: "SecureOS/([0-9.]+)((\\.H|P|E)([0-9]+))?", string: banner );
											if( !isnull( version[1] ) && !isnull( version[4] ) ){
												version[3] = str_replace( string: version[3], find: ".H", replace: "H" );
												os_register_and_report( os: "Secure64 SecureOS", version: version[1], patch: version[3] + version[4], cpe: "cpe:/o:secure64:secureos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( !isnull( version[1] ) ){
													os_register_and_report( os: "Secure64 SecureOS", version: version[1], cpe: "cpe:/o:secure64:secureos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													os_register_and_report( os: "Secure64 SecureOS", cpe: "cpe:/o:secure64:secureos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
											}
										}
										else {
											if( ContainsString( banner_lo, "vxworks" ) ){
												os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( IsMatchRegexp( banner, "Darwin[0-9/]" ) ){
													os_register_and_report( os: "Apple Mac OS X / macOS / iOS", cpe: "cpe:/o:apple:mac_os_x", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													if( IsMatchRegexp( banner, "^QNX" ) ){
														version = eregmatch( pattern: "QNX/([0-9.]+)", string: banner );
														if( !isnull( version[1] ) ){
															os_register_and_report( os: "QNX Neutrino Realtime Operating System", version: version[1], cpe: "cpe:/o:blackberry:qnx_neutrino_rtos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
														else {
															os_register_and_report( os: "QNX Neutrino Realtime Operating System", cpe: "cpe:/o:blackberry:qnx_neutrino_rtos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
													}
													else {
														if( ContainsString( banner_lo, "isilon onefs" ) ){
															version = eregmatch( pattern: "Isilon OneFS/v([0-9.]+)", string: banner );
															if( !isnull( version[1] ) ){
																os_register_and_report( os: "Dell EMC Isilon OneFS", version: version[1], cpe: "cpe:/o:emc:isilon_onefs", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
															else {
																os_register_and_report( os: "Dell EMC Isilon OneFS", cpe: "cpe:/o:emc:isilon_onefs", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
														}
														else {
															if( IsMatchRegexp( banner, "^GBOS" ) ){
																version = eregmatch( pattern: "GBOS/([0-9.]+)", string: banner );
																if( !isnull( version[1] ) ){
																	os_register_and_report( os: "GTA GB-OS", version: version[1], cpe: "cpe:/o:gta:gb-os", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	os_register_and_report( os: "GTA GB-OS", cpe: "cpe:/o:gta:gb-os", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
															}
															else {
																if( ContainsString( banner_lo, "ecos-ecos" ) || IsMatchRegexp( banner, "^ecos" ) ){
																	os_register_and_report( os: "eCos RTOS", cpe: "cpe:/o:ecoscentric:ecos_rtos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	if( IsMatchRegexp( banner, "^BRIX" ) ){
																		os_register_and_report( os: "BRiX", cpe: "cpe:/o:brix:brix", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																	}
																	else {
																		if( ContainsString( banner_lo, "eq/os" ) ){
																			version = eregmatch( pattern: "EQ/OS_([0-9.]+)(-RELEASE-(p[0-9]+))?", string: banner );
																			if( !isnull( version[1] ) && !isnull( version[3] ) ){
																				os_register_and_report( os: "Fortinet EQ/OS", version: version[1], patch: version[3], cpe: "cpe:/o:fortinet:eq%2Fos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																			}
																			else {
																				if( !isnull( version[1] ) ){
																					os_register_and_report( os: "Fortinet EQ/OS", version: version[1], cpe: "cpe:/o:fortinet:eq%2Fos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																				else {
																					os_register_and_report( os: "Fortinet EQ/OS", cpe: "cpe:/o:fortinet:eq%2Fos", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																			}
																		}
																		else {
																			if( ContainsString( banner_lo, "chiaros" ) ){
																				version = eregmatch( pattern: "Chiaros/([0-9.]+)", string: banner );
																				if( !isnull( version[1] ) ){
																					os_register_and_report( os: "Chiaro Networks Chiaros", version: version[1], cpe: "cpe:/o:chiaro:chiaros", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																				else {
																					os_register_and_report( os: "Chiaro Networks Chiaros", cpe: "cpe:/o:chiaro:chiaros", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																			}
																			else {
																				if( ContainsString( banner_lo, "mitautm" ) ){
																					version = eregmatch( pattern: "MitaUTM/([0-9.]+)(-RELEASE-(p[0-9]+))?", string: banner );
																					if( !isnull( version[1] ) && !isnull( version[3] ) ){
																						os_register_and_report( os: "MitaUTM", version: version[1], patch: version[3], cpe: "cpe:/o:mitautm:mitautm", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																					}
																					else {
																						if( !isnull( version[1] ) ){
																							os_register_and_report( os: "MitaUTM", version: version[1], cpe: "cpe:/o:mitautm:mitautm", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																						}
																						else {
																							os_register_and_report( os: "MitaUTM", cpe: "cpe:/o:mitautm:mitautm", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																						}
																					}
																				}
																				else {
																					if( ContainsString( banner_lo, "moscad ace" ) ){
																						os_register_and_report( os: "Motorola Moscad ACE", cpe: "cpe:/o:motorola:moscad_ace_firmware", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																					}
																					else {
																						if( ContainsString( banner_lo, "unixware" ) ){
																							os_register_and_report( os: "Univel/Novell/SCO/Xinuos UnixWare", cpe: "cpe:/o:xinuos:unixware", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																						}
																						else {
																							if( ContainsString( banner_lo, "brickstoros" ) ){
																								version = eregmatch( pattern: "BrickStorOS/([0-9.]+)", string: banner );
																								if( !isnull( version[1] ) ){
																									os_register_and_report( os: "RackTop Systems BrickStor OS", version: version[1], cpe: "cpe:/o:racktopsystems:brickstoros", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																								}
																								else {
																									os_register_and_report( os: "RackTop Systems BrickStor OS", cpe: "cpe:/o:racktopsystems:brickstoros", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																								}
																							}
																							else {
																								if( IsMatchRegexp( banner, "^VMkernel" ) ){
																									version = eregmatch( pattern: "VMkernel/([0-9.]+)", string: banner );
																									if( !isnull( version[1] ) ){
																										os_register_and_report( os: "VMware VMkernel", version: version[1], cpe: "cpe:/o:vmware:vmkernel", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																									}
																									else {
																										os_register_and_report( os: "VMware VMkernel", cpe: "cpe:/o:vmware:vmkernel", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																									}
																								}
																								else {
																									if( ContainsString( banner_lo, "cisco" ) ){
																										os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																									}
																									else {
																										os_register_and_report( os: banner, banner_type: BANNER_TYPE, banner: banner, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
																										os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "ntp_banner", port: port, proto: "udp" );
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
exit( 0 );

