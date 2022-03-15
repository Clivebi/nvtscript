if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108192" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-07-17 09:13:48 +0100 (Mon, 17 Jul 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (MySQL/MariaDB)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc" );
	script_mandatory_keys( "MySQL_MariaDB/installed" );
	script_tag( name: "summary", value: "MySQL/MariaDB server banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (MySQL/MariaDB)";
BANNER_TYPE = "MySQL/MariaDB server banner";
cpe_list = make_list( "cpe:/a:oracle:mysql",
	 "cpe:/a:mariadb:mariadb" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
if(!banner = get_kb_item( "mysql_mariadb/full_banner/" + port )){
	exit( 0 );
}
CPE = infos["cpe"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(egrep( pattern: "^[0-9.]+(-[0-9.]+)?-(rc|MariaDB|MariaDB-log|MariaDB-[0-9]+|log|enterprise-gpl-log|enterprise-gpl-pro|enterprise-gpl-pro-log|enterprise-gpl-advanced|enterprise-commercial-advanced-log|enterprise-commercial-advanced)$", string: banner )){
	exit( 0 );
}
if(egrep( pattern: "^[0-9.]+$", string: banner )){
	exit( 0 );
}
if( ContainsString( banner, "ubuntu0.04.10" ) || ContainsString( banner, "~warty" ) || ContainsString( banner, ".warty." ) ){
	os_register_and_report( os: "Ubuntu", version: "4.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
else {
	if( ContainsString( banner, "ubuntu0.05.04" ) || ContainsString( banner, "~hoary" ) || ContainsString( banner, ".hoary." ) ){
		os_register_and_report( os: "Ubuntu", version: "5.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	else {
		if( ContainsString( banner, "ubuntu0.05.10" ) || ContainsString( banner, "~breezy" ) || ContainsString( banner, ".breezy." ) ){
			os_register_and_report( os: "Ubuntu", version: "5.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		else {
			if( ContainsString( banner, "ubuntu0.06.06" ) || ContainsString( banner, "~dapper" ) || ContainsString( banner, ".dapper." ) ){
				os_register_and_report( os: "Ubuntu", version: "6.06", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			else {
				if( ContainsString( banner, "ubuntu0.06.10" ) || ContainsString( banner, "~edgy" ) || ContainsString( banner, ".edgy." ) ){
					os_register_and_report( os: "Ubuntu", version: "6.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					exit( 0 );
				}
				else {
					if( ContainsString( banner, "ubuntu0.07.04" ) || ContainsString( banner, "~feisty" ) || ContainsString( banner, ".feisty." ) ){
						os_register_and_report( os: "Ubuntu", version: "7.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						exit( 0 );
					}
					else {
						if( ContainsString( banner, "ubuntu0.07.10" ) || ContainsString( banner, "~gutsy" ) || ContainsString( banner, ".gutsy." ) ){
							os_register_and_report( os: "Ubuntu", version: "7.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							exit( 0 );
						}
						else {
							if( ContainsString( banner, "ubuntu0.08.04" ) || ContainsString( banner, "~hardy" ) || ContainsString( banner, ".hardy." ) ){
								os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								exit( 0 );
							}
							else {
								if( ContainsString( banner, "ubuntu0.08.10" ) || ContainsString( banner, "~intrepid" ) || ContainsString( banner, ".intrepid." ) ){
									os_register_and_report( os: "Ubuntu", version: "8.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									exit( 0 );
								}
								else {
									if( ContainsString( banner, "ubuntu0.09.04" ) || ContainsString( banner, "~jaunty" ) || ContainsString( banner, ".jaunty." ) ){
										os_register_and_report( os: "Ubuntu", version: "9.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										exit( 0 );
									}
									else {
										if( ContainsString( banner, "ubuntu0.09.10" ) || ContainsString( banner, "~karmic" ) || ContainsString( banner, ".karmic." ) ){
											os_register_and_report( os: "Ubuntu", version: "9.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											exit( 0 );
										}
										else {
											if( ContainsString( banner, "ubuntu0.10.04" ) || ContainsString( banner, "~lucid" ) || ContainsString( banner, ".lucid." ) ){
												os_register_and_report( os: "Ubuntu", version: "10.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												exit( 0 );
											}
											else {
												if( ContainsString( banner, "ubuntu0.10.10" ) || ContainsString( banner, "~maverick" ) || ContainsString( banner, ".maverick." ) ){
													os_register_and_report( os: "Ubuntu", version: "10.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													exit( 0 );
												}
												else {
													if( ContainsString( banner, "ubuntu0.11.04" ) || ContainsString( banner, "~natty" ) || ContainsString( banner, ".natty." ) ){
														os_register_and_report( os: "Ubuntu", version: "11.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														exit( 0 );
													}
													else {
														if( ContainsString( banner, "ubuntu0.11.10" ) || ContainsString( banner, "~oneiric" ) || ContainsString( banner, ".oneiric." ) ){
															os_register_and_report( os: "Ubuntu", version: "11.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															exit( 0 );
														}
														else {
															if( ContainsString( banner, "ubuntu0.12.04" ) || ContainsString( banner, "~precise" ) || ContainsString( banner, ".precise." ) ){
																os_register_and_report( os: "Ubuntu", version: "12.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																exit( 0 );
															}
															else {
																if( ContainsString( banner, "ubuntu0.12.10" ) || ContainsString( banner, "~quantal" ) || ContainsString( banner, ".quantal." ) ){
																	os_register_and_report( os: "Ubuntu", version: "12.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	exit( 0 );
																}
																else {
																	if( ContainsString( banner, "ubuntu0.13.04" ) || ContainsString( banner, "~raring" ) || ContainsString( banner, ".raring." ) ){
																		os_register_and_report( os: "Ubuntu", version: "13.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		exit( 0 );
																	}
																	else {
																		if( ContainsString( banner, "ubuntu0.13.10" ) || ContainsString( banner, "~saucy" ) || ContainsString( banner, ".saucy." ) ){
																			os_register_and_report( os: "Ubuntu", version: "13.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			exit( 0 );
																		}
																		else {
																			if( ContainsString( banner, "ubuntu0.14.04" ) || ContainsString( banner, "~trusty" ) || ContainsString( banner, ".trusty." ) ){
																				os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																				exit( 0 );
																			}
																			else {
																				if( ContainsString( banner, "ubuntu0.14.10" ) || ContainsString( banner, "~utopic" ) || ContainsString( banner, ".utopic." ) ){
																					os_register_and_report( os: "Ubuntu", version: "14.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																					exit( 0 );
																				}
																				else {
																					if( ContainsString( banner, "ubuntu0.15.04" ) || ContainsString( banner, "~vivid" ) || ContainsString( banner, ".vivid." ) ){
																						os_register_and_report( os: "Ubuntu", version: "15.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																						exit( 0 );
																					}
																					else {
																						if( ContainsString( banner, "ubuntu0.15.10" ) || ContainsString( banner, "~wily" ) || ContainsString( banner, ".wily." ) ){
																							os_register_and_report( os: "Ubuntu", version: "15.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																							exit( 0 );
																						}
																						else {
																							if( ContainsString( banner, "ubuntu0.16.04" ) || ContainsString( banner, "~xenial" ) || ContainsString( banner, ".xenial." ) ){
																								os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																								exit( 0 );
																							}
																							else {
																								if( ContainsString( banner, "ubuntu0.16.10" ) || ContainsString( banner, "~yakkety" ) || ContainsString( banner, ".yakkety." ) ){
																									os_register_and_report( os: "Ubuntu", version: "16.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																									exit( 0 );
																								}
																								else {
																									if( ContainsString( banner, "ubuntu0.17.04" ) || ContainsString( banner, "~zesty" ) || ContainsString( banner, ".zesty." ) ){
																										os_register_and_report( os: "Ubuntu", version: "17.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																										exit( 0 );
																									}
																									else {
																										if( ContainsString( banner, "ubuntu0.17.10" ) || ContainsString( banner, "~artful" ) || ContainsString( banner, ".artful." ) ){
																											os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																											exit( 0 );
																										}
																										else {
																											if( ContainsString( banner, "ubuntu0.18.04" ) || ContainsString( banner, "~bionic" ) || ContainsString( banner, ".bionic." ) ){
																												os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																												exit( 0 );
																											}
																											else {
																												if( ContainsString( banner, "ubuntu0.18.10" ) || ContainsString( banner, "10.1.29-6ubuntu2" ) || ContainsString( banner, "~cosmic" ) || ContainsString( banner, ".cosmic." ) ){
																													os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																													exit( 0 );
																												}
																												else {
																													if( ContainsString( banner, "ubuntu0.19.04" ) || ContainsString( banner, "~disco" ) || ContainsString( banner, ".disco." ) ){
																														os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																														exit( 0 );
																													}
																													else {
																														if( ContainsString( banner, "ubuntu0.19.10" ) || ContainsString( banner, "~eoan" ) || ContainsString( banner, ".eoan." ) ){
																															os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																															exit( 0 );
																														}
																														else {
																															if(ContainsString( banner, "5.5.5-10.3.22-MariaDB-1ubuntu1" ) || ContainsString( banner, "ubuntu0.20.04" ) || ContainsString( banner, "~focal" ) || ContainsString( banner, ".focal." )){
																																os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
if(ContainsString( banner, "ubuntu" )){
	os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "+deb" ) || ContainsString( banner, "~jessie" ) || ContainsString( banner, "~wheezy" ) || ContainsString( banner, "~stretch" ) || ContainsString( banner, "etch" ) || ContainsString( banner, "-Debian" ) || ContainsString( banner, "~buster" ) || ContainsString( banner, "squeeze" ) || ContainsString( banner, "lenny" ) || ContainsString( banner, "~bpo" )){
	if( ContainsString( banner, "etch" ) ){
		os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		if( ContainsString( banner, "lenny" ) ){
			os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( banner, "squeeze" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "~wheezy" ) || ContainsString( banner, "~bpo7" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "+deb8" ) || ContainsString( banner, "~jessie" ) || ContainsString( banner, "~bpo8" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "+deb9" ) || ContainsString( banner, "~stretch" ) || ContainsString( banner, "~bpo9" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "+deb10" ) || ContainsString( banner, "~buster" ) || ContainsString( banner, "~bpo10" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
						}
					}
				}
			}
		}
	}
	exit( 0 );
}
if(ContainsString( banner, "-enterprise-nt" ) || ContainsString( banner, "-enterprise-gpl-nt" ) || ContainsString( banner, "-pro-gpl-nt" ) || ContainsString( banner, "-community-nt" ) || ContainsString( banner, "-nt-log" ) || ContainsString( banner, "-nt-max" ) || IsMatchRegexp( banner, "^[0-9.]+-nt$" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "mysql_mariadb_banner", port: port );
exit( 0 );

