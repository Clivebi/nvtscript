if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108200" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (UPnP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_upnp_detect.sc" );
	script_require_udp_ports( "Services/udp/upnp", 1900 );
	script_mandatory_keys( "upnp/identified" );
	script_tag( name: "summary", value: "UPnP protocol based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (UPnP)";
BANNER_TYPE = "UPnP protocol banner";
port = service_get_port( default: 1900, ipproto: "udp", proto: "upnp" );
if(!banner = get_kb_item( "upnp/" + port + "/banner" )){
	exit( 0 );
}
if(ContainsString( banner, "FRITZ!Box" )){
	os_register_and_report( os: "AVM FRITZ!OS", cpe: "cpe:/o:avm:fritz%21_os", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "AVM FRITZ!WLAN Repeater" )){
	os_register_and_report( os: "AVM FRITZ!WLAN Repeater", cpe: "cpe:/o:avm:fritz%21wlan_repeater", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(egrep( pattern: "VxWorks", string: banner, icase: TRUE )){
	os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
}
if(egrep( pattern: "^SERVER: Linux", string: banner, icase: TRUE )){
	version = eregmatch( pattern: "Server: Linux(/|\\-)([0-9.x]+)", string: banner, icase: TRUE );
	if( !isnull( version[2] ) ){
		os_register_and_report( os: "Linux", version: version[2], cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(egrep( pattern: "^SERVER: Ubuntu", string: banner, icase: TRUE )){
	version = eregmatch( pattern: "SERVER: Ubuntu/([0-9.]+)", string: banner, icase: TRUE );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Ubuntu", version: version[1], cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		if( ContainsString( banner, "Ubuntu/warty" ) ){
			os_register_and_report( os: "Ubuntu", version: "4.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( banner, "Ubuntu/hoary" ) ){
				os_register_and_report( os: "Ubuntu", version: "5.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "Ubuntu/breezy" ) ){
					os_register_and_report( os: "Ubuntu", version: "5.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "Ubuntu/dapper" ) ){
						os_register_and_report( os: "Ubuntu", version: "6.06", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "Ubuntu/edgy" ) ){
							os_register_and_report( os: "Ubuntu", version: "6.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "Ubuntu/feisty" ) ){
								os_register_and_report( os: "Ubuntu", version: "7.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( banner, "Ubuntu/gutsy" ) ){
									os_register_and_report( os: "Ubuntu", version: "7.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( banner, "Ubuntu/hardy" ) ){
										os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( banner, "Ubuntu/intrepid" ) ){
											os_register_and_report( os: "Ubuntu", version: "8.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( banner, "Ubuntu/jaunty" ) ){
												os_register_and_report( os: "Ubuntu", version: "9.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( banner, "Ubuntu/karmic" ) ){
													os_register_and_report( os: "Ubuntu", version: "9.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													if( ContainsString( banner, "Ubuntu/lucid" ) ){
														os_register_and_report( os: "Ubuntu", version: "10.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													}
													else {
														if( ContainsString( banner, "Ubuntu/maverick" ) ){
															os_register_and_report( os: "Ubuntu", version: "10.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
														else {
															if( ContainsString( banner, "Ubuntu/natty" ) ){
																os_register_and_report( os: "Ubuntu", version: "11.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
															else {
																if( ContainsString( banner, "Ubuntu/oneiric" ) ){
																	os_register_and_report( os: "Ubuntu", version: "11.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	if( ContainsString( banner, "Ubuntu/precise" ) ){
																		os_register_and_report( os: "Ubuntu", version: "12.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	}
																	else {
																		if( ContainsString( banner, "Ubuntu/quantal" ) ){
																			os_register_and_report( os: "Ubuntu", version: "12.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		}
																		else {
																			if( ContainsString( banner, "Ubuntu/raring" ) ){
																				os_register_and_report( os: "Ubuntu", version: "13.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			}
																			else {
																				if( ContainsString( banner, "Ubuntu/saucy" ) ){
																					os_register_and_report( os: "Ubuntu", version: "13.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																				else {
																					if( ContainsString( banner, "Ubuntu/trusty" ) ){
																						os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																					}
																					else {
																						if( ContainsString( banner, "Ubuntu/utopic" ) ){
																							os_register_and_report( os: "Ubuntu", version: "14.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																						}
																						else {
																							if( ContainsString( banner, "Ubuntu/vivid" ) ){
																								os_register_and_report( os: "Ubuntu", version: "15.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																							}
																							else {
																								if( ContainsString( banner, "Ubuntu/wily" ) ){
																									os_register_and_report( os: "Ubuntu", version: "15.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																								}
																								else {
																									if( ContainsString( banner, "Ubuntu/xenial" ) ){
																										os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																									}
																									else {
																										if( ContainsString( banner, "Ubuntu/yakkety" ) ){
																											os_register_and_report( os: "Ubuntu", version: "16.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																										}
																										else {
																											if( ContainsString( banner, "Ubuntu/zesty" ) ){
																												os_register_and_report( os: "Ubuntu", version: "17.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																											}
																											else {
																												if( ContainsString( banner, "Ubuntu/artful" ) ){
																													os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																												}
																												else {
																													if( ContainsString( banner, "Ubuntu/bionic" ) ){
																														os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																													}
																													else {
																														if( ContainsString( banner, "Ubuntu/cosmic" ) ){
																															os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																														}
																														else {
																															if( ContainsString( banner, "Ubuntu/disco" ) ){
																																os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																															}
																															else {
																																if( ContainsString( banner, "Ubuntu/eoan" ) ){
																																	os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																}
																																else {
																																	if( ContainsString( banner, "Ubuntu/focal" ) ){
																																		os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																	}
																																	else {
																																		os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
	exit( 0 );
}
if(egrep( pattern: "^Server: Debian", string: banner, icase: TRUE )){
	version = eregmatch( pattern: "Server: Debian/([0-9.]+)", string: banner, icase: TRUE );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		if( ContainsString( banner, "Debian/buster" ) ){
			os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( banner, "Debian/stretch" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "Debian/jessie" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "Debian/wheezy" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "Debian/squeeze" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "Debian/lenny" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( banner, "Debian/etch" ) ){
									os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( banner, "Debian/sarge" ) ){
										os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( banner, "Debian/woody" ) ){
											os_register_and_report( os: "Debian GNU/Linux", version: "3.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( banner, "Debian/potato" ) ){
												os_register_and_report( os: "Debian GNU/Linux", version: "2.2", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( banner, "Debian/slink" ) ){
													os_register_and_report( os: "Debian GNU/Linux", version: "2.1", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													if( ContainsString( banner, "Debian/hamm" ) ){
														os_register_and_report( os: "Debian GNU/Linux", version: "2.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													}
													else {
														if( ContainsString( banner, "Debian/bo" ) ){
															os_register_and_report( os: "Debian GNU/Linux", version: "1.3", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
														else {
															if( ContainsString( banner, "Debian/rex" ) ){
																os_register_and_report( os: "Debian GNU/Linux", version: "1.2", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
															else {
																if( ContainsString( banner, "Debian/buzz" ) ){
																	os_register_and_report( os: "Debian GNU/Linux", version: "1.1", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
}
if(egrep( pattern: "^Server: CentOS", string: banner, icase: TRUE )){
	version = eregmatch( pattern: "Server: CentOS/([0-9.]+)", string: banner, icase: TRUE );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "CentOS", version: version[1], cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, " iBMC/" )){
	os_register_and_report( os: "Huawei iBMC Firmware", cpe: "cpe:/o:huawei:ibmc_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(egrep( pattern: "SERVER\\s*:\\s*Loxone Miniserver", string: banner, icase: TRUE )){
	os_register_and_report( os: "Loxone Miniserver Firmware", cpe: "cpe:/o:loxone:miniserver_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(egrep( pattern: "SERVER\\s*:\\s*FOS.+Jupiter", string: banner, icase: TRUE )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "upnp_banner", port: port, proto: "udp" );
exit( 0 );

