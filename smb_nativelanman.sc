if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102011" );
	script_version( "2021-09-06T06:22:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 06:22:50 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-18 16:06:42 +0200 (Fri, 18 Sep 2009)" );
	script_name( "SMB NativeLanMan" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_dependencies( "cifs445.sc", "netbios_name_get.sc" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "It is possible to extract OS, domain and SMB server information
  from the Session Setup AndX Response packet which is generated during NTLM authentication." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("string_hex_func.inc.sc");
require("smb_nt.inc.sc");
require("global_settings.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cpe.inc.sc");
SCRIPT_DESC = "SMB NativeLanMan";
port = kb_smb_transport();
name = kb_smb_name();
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = smb_session_request( soc: soc, remote: name );
if(!r){
	close( soc );
	exit( 0 );
}
prot = smb_neg_prot_NTLMv1( soc: soc );
if(!prot){
	close( soc );
	exit( 0 );
}
cs = smb_neg_prot_cs( prot: prot );
ret = smb_session_setup_NTLMvN( soc: soc, login: "", password: "", domain: "", cs: cs, version: 1 );
if(!ret){
	close( soc );
	exit( 0 );
}
close( soc );
s = hexstr( ret );
l = strlen( s );
c = 0;
out = NULL;
for(x = l - 3;x > 0 && c < 3;x = x - 2){
	if( ( s[x] + s[x - 1] ) == "00" ){
		c++;
		if(c == 1){
			wg_str = hex2raw( s: out );
			if(wg_str && !isnull( wg_str )){
				set_kb_item( name: "SMB/workgroup", value: wg_str );
				set_kb_item( name: "SMB/DOMAIN", value: wg_str );
				info = "Detected SMB workgroup: " + wg_str + "\n";
				result += info;
				report = TRUE;
			}
		}
		if(c == 2){
			smb_str = hex2raw( s: out );
			smb_str_lo = tolower( smb_str );
			if(smb_str && !isnull( smb_str )){
				set_kb_item( name: "SMB/NativeLanManager", value: smb_str );
				set_kb_item( name: "SMB/SERVER", value: smb_str );
				info = "Detected SMB server: " + smb_str + "\n";
				result += info;
				report = TRUE;
			}
			if(ContainsString( smb_str_lo, "samba" )){
				version = "unknown";
				install = port + "/tcp";
				vers = eregmatch( string: smb_str, pattern: "Samba ([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?" );
				if(vers[1]){
					version = vers[1];
					if(vers[2]){
						version += vers[2];
					}
				}
				is_samba = TRUE;
				set_kb_item( name: "SMB/samba", value: TRUE );
				set_kb_item( name: "samba/smb_or_ssh/detected", value: TRUE );
				set_kb_item( name: "samba/smb/detected", value: TRUE );
				cpe = build_cpe( value: version, exp: "([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?", base: "cpe:/a:samba:samba:" );
				if(!cpe){
					cpe = "cpe:/a:samba:samba";
				}
				register_product( cpe: cpe, location: install, port: port, service: "smb" );
				log_message( data: build_detection_report( app: "Samba", version: version, install: install, cpe: cpe, concluded: smb_str, extra: result ), port: port );
			}
		}
		if(c == 3){
			os_str = hex2raw( s: out );
			if(os_str && !isnull( os_str )){
				banner_type = "SMB/Samba banner";
				os_str_lo = tolower( os_str );
				if(is_samba || IsMatchRegexp( smb_str, "(SUSE|Debian|Ubuntu|Unix|SunOS|vxworks|Native SMB service|Linux)" ) || os_str == "QTS" || ContainsString( os_str, "Apple Base Station" )){
					linux_found = TRUE;
				}
				banner = "\nOS String:  " + os_str;
				banner += "\nSMB String: " + smb_str;
				if(ContainsString( os_str_lo, "windows" ) && linux_found){
					banner += "\nNote: The service is running on a Linux/Unix based OS but reporting itself with an Windows related OS string.";
				}
				if( ContainsString( smb_str_lo, "debian" ) ){
					if( ContainsString( smb_str, "Samba 4.2.10-Debian" ) || ContainsString( smb_str, "Samba 4.2.14-Debian" ) ){
						os_str = "Debian GNU/Linux 8";
						os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( smb_str, "Samba 4.5.8-Debian" ) || ContainsString( smb_str, "Samba 4.5.12-Debian" ) || ContainsString( smb_str, "Samba 4.5.16-Debian" ) ){
							os_str = "Debian GNU/Linux 9";
							os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( smb_str, "Samba 4.9.5-Debian" ) ){
								os_str = "Debian GNU/Linux 10";
								os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_str = "Debian GNU/Linux";
								os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
						}
					}
				}
				else {
					if( ContainsString( smb_str, "SUSE" ) ){
						if( ContainsString( smb_str, "CODE11" ) ){
							os_str = "SUSE Linux Enterprise Server 11";
							os_register_and_report( os: "SUSE Linux Enterprise Server", version: "11", cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( smb_str, "SLE_12" ) ){
								os_str = "SUSE Linux Enterprise Server 12 / openSUSE LEAP 42.2";
								os_register_and_report( os: "SUSE Linux Enterprise Server (or openSUSE LEAP 42.2)", version: "12", cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								sl_ver = eregmatch( pattern: "SUSE-SL([0-9.]+)", string: smb_str );
								if( sl_ver[1] ){
									os_str = "SUSE Linux Enterprise " + sl_ver[1];
									os_register_and_report( os: "SUSE Linux Enterprise", version: sl_ver[1], cpe: "cpe:/o:suse:linux_enterprise", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									os_str = "Unknown SUSE Release";
									os_register_and_report( os: "Unknown SUSE Linux release", cpe: "cpe:/o:suse:unknown_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "smb_samba_banner", port: port );
								}
							}
						}
					}
					else {
						if( ContainsString( smb_str_lo, "ubuntu" ) ){
							if( ContainsString( smb_str, "Samba 3.0.7-Ubuntu" ) ){
								os_str = "Ubuntu 4.10";
								os_register_and_report( os: "Ubuntu", version: "4.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( smb_str, "Samba 3.0.10-Ubuntu" ) ){
									os_str = "Ubuntu 5.04";
									os_register_and_report( os: "Ubuntu", version: "5.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( smb_str, "Samba 3.0.14a-Ubuntu" ) ){
										os_str = "Ubuntu 5.10";
										os_register_and_report( os: "Ubuntu", version: "5.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( smb_str, "Samba 4.1.6-Ubuntu" ) ){
											os_str = "Ubuntu 14.04";
											os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( smb_str, "Samba 4.1.11-Ubuntu" ) ){
												os_str = "Ubuntu 14.10";
												os_register_and_report( os: "Ubuntu", version: "14.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( smb_str, "Samba 4.1.13-Ubuntu" ) ){
													os_str = "Ubuntu 15.04";
													os_register_and_report( os: "Ubuntu", version: "15.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													if( ContainsString( smb_str, "Samba 4.1.17-Ubuntu" ) ){
														os_str = "Ubuntu 15.10";
														os_register_and_report( os: "Ubuntu", version: "15.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													}
													else {
														if( ContainsString( smb_str, "Samba 4.3.8-Ubuntu" ) ){
															os_str = "Ubuntu 16.04";
															os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
														else {
															if( ContainsString( smb_str, "Samba 4.3.11-Ubuntu" ) || ContainsString( smb_str, "Samba 4.3.9-Ubuntu" ) ){
																os_str = "Ubuntu 14.04 or Ubuntu 16.04";
																os_register_and_report( os: "Ubuntu 14.04 or 16.04", cpe: "cpe:/o:canonical:ubuntu_linux:16.04", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
															else {
																if( ContainsString( smb_str, "Samba 4.4.5-Ubuntu" ) ){
																	os_str = "Ubuntu 16.10";
																	os_register_and_report( os: "Ubuntu", version: "16.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	if( ContainsString( smb_str, "Samba 4.5.8-Ubuntu" ) || ContainsString( smb_str, "Samba 4.5.4-Ubuntu" ) ){
																		os_str = "Ubuntu 17.04";
																		os_register_and_report( os: "Ubuntu", version: "17.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	}
																	else {
																		if( ContainsString( smb_str, "Samba 4.6.7-Ubuntu" ) ){
																			os_str = "Ubuntu 17.10";
																			os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		}
																		else {
																			if( ContainsString( smb_str, "Samba 4.7.6-Ubuntu" ) ){
																				os_str = "Ubuntu 18.04";
																				os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			}
																			else {
																				if( ContainsString( smb_str, "Samba 4.8.4-Ubuntu" ) ){
																					os_str = "Ubuntu 18.10";
																					os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																				else {
																					if( ContainsString( smb_str, "Samba 4.10.0-Ubuntu" ) ){
																						os_str = "Ubuntu 19.04";
																						os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																					}
																					else {
																						if( ContainsString( smb_str, "Samba 4.10.7-Ubuntu" ) ){
																							os_str = "Ubuntu 19.10";
																							os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																						}
																						else {
																							os_str = "Unknown Ubuntu Release";
																							os_register_and_report( os: "Unknown Ubuntu release", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																							os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "smb_samba_banner", port: port );
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
						else {
							if( ContainsString( os_str_lo, "vxworks" ) ){
								set_kb_item( name: "smb/windriver/vxworks/detected", value: TRUE );
								os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( os_str == "QTS" ){
									os_register_and_report( os: "QNAP QTS", cpe: "cpe:/o:qnap:qts", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( os_str, "Apple Base Station" ) ){
										os_register_and_report( os: "Apple Base Station Firmware", cpe: "cpe:/o:apple:base_station_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( os_str, "SunOS" ) ){
											sun_ver = eregmatch( pattern: "SunOS ([0-9.]+)", string: os_str );
											if( sun_ver[1] ){
												os_register_and_report( os: "SunOS", version: sun_ver[1], cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
										}
										else {
											if( ContainsString( os_str_lo, "unix" ) && ContainsString( smb_str, ".el" ) ){
												version = eregmatch( pattern: "\\.el([0-9]+)", string: smb_str );
												if( !isnull( version[1] ) ){
													os_register_and_report( os: "Red Hat Enterprise Linux / CentOS", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													os_register_and_report( os: "Red Hat Enterprise Linux / CentOS", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
											}
											else {
												if( ContainsString( os_str_lo, "unix" ) || ContainsString( os_str_lo, "linux" ) ){
													os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													if(os_str_lo != "unix" && !IsMatchRegexp( smb_str, "^Samba [0-9.]+$" )){
														os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "smb_samba_banner", port: port );
													}
												}
												else {
													if( ContainsString( os_str_lo, "windows" ) && linux_found ){
														os_str = "Linux/Unix";
														os_register_and_report( os: os_str, cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														if(!eregmatch( string: smb_str, pattern: "^Samba ([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?$", icase: FALSE )){
															os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "smb_samba_banner", port: port );
														}
													}
													else {
														if( ContainsString( os_str_lo, "windows" ) && !linux_found ){
															if( ContainsString( os_str_lo, "windows 10 " ) ){
																cpe = "cpe:/o:microsoft:windows_10";
																if( ver = get_version_from_build( string: os_str, win_name: "win10" ) ) {
																	cpe += ":" + tolower( ver );
																}
																else {
																	cpe += ":";
																}
																if( ContainsString( os_str_lo, "ltsb" ) ) {
																	cpe += ":ltsb";
																}
																else {
																	if( ContainsString( os_str_lo, "ltsc" ) ) {
																		cpe += ":ltsc";
																	}
																	else {
																		cpe += ":cb";
																	}
																}
																if( ContainsString( os_str_lo, "enterprise" ) ) {
																	cpe += ":enterprise";
																}
																else {
																	if( ContainsString( os_str_lo, "education" ) ) {
																		cpe += ":education";
																	}
																	else {
																		if( ContainsString( os_str_lo, "home" ) ) {
																			cpe += ":home";
																		}
																		else {
																			if( ContainsString( os_str_lo, "pro" ) ) {
																				cpe += ":pro";
																			}
																			else {
																				cpe += ":unknown_edition";
																			}
																		}
																	}
																}
																os_register_and_report( os: os_str, version: ver, cpe: cpe, full_cpe: TRUE, banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
															}
															else {
																if( ContainsString( os_str_lo, "windows server 2019" ) ){
																	cpe = "cpe:/o:microsoft:windows_server_2019";
																	if( ver = get_version_from_build( string: os_str, win_name: "win10" ) ) {
																		cpe += ":" + tolower( ver ) + ":";
																	}
																	else {
																		cpe += "::";
																	}
																	if( ContainsString( os_str_lo, "datacenter" ) ) {
																		cpe += ":datacenter";
																	}
																	else {
																		if( ContainsString( os_str_lo, "standard" ) ) {
																			cpe += ":standard";
																		}
																		else {
																			cpe += ":unknown_edition";
																		}
																	}
																	os_register_and_report( os: os_str, version: ver, cpe: cpe, full_cpe: TRUE, banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																}
																else {
																	if( ContainsString( os_str_lo, "windows embedded" ) ){
																		cpe = "cpe:/o:microsoft:windows_embedded";
																		if( ContainsString( os_str_lo, "8.1" ) ) {
																			cpe += "_8.1:";
																		}
																		else {
																			if( ContainsString( os_str_lo, "7601" ) ) {
																				cpe += "_7:-:sp1:";
																			}
																			else {
																				if( ContainsString( os_str_lo, "7600" ) ) {
																					cpe += "_7:-:-:";
																				}
																				else {
																					cpe += ":-:-:";
																				}
																			}
																		}
																		if( ContainsString( os_str_lo, "compact" ) ) {
																			cpe += "compact";
																		}
																		else {
																			if( ContainsString( os_str_lo, "standard" ) ) {
																				cpe += "standard";
																			}
																			else {
																				if( ContainsString( os_str_lo, "enterprise" ) ) {
																					cpe += "enterprise";
																				}
																				else {
																					if( ContainsString( os_str_lo, "server" ) ) {
																						cpe += "server";
																					}
																					else {
																						if( ContainsString( os_str_lo, "industry" ) ) {
																							cpe += "industry";
																						}
																						else {
																							if( ContainsString( os_str_lo, "navready" ) ) {
																								cpe += "navready";
																							}
																							else {
																								if( ContainsString( os_str_lo, "automotive" ) ) {
																									cpe += "automotive";
																								}
																								else {
																									if( ContainsString( os_str_lo, "handheld" ) ) {
																										cpe += "handheld";
																									}
																									else {
																										if(ContainsString( os_str_lo, "pro" )){
																											cpe += "pro";
																										}
																									}
																								}
																							}
																						}
																					}
																				}
																			}
																		}
																		os_register_and_report( os: os_str, cpe: cpe, banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																	}
																	else {
																		if( ContainsString( os_str_lo, "windows 5.1" ) && ContainsString( smb_str_lo, "windows 2000 lan manager" ) ){
																			os_register_and_report( os: "Windows XP", cpe: "cpe:/o:microsoft:windows_xp", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																		}
																		else {
																			if( ContainsString( os_str_lo, "windows 5.0" ) && ContainsString( smb_str_lo, "windows 2000 lan manager" ) ){
																				os_register_and_report( os: "Windows 2000", cpe: "cpe:/o:microsoft:windows_2000", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																			}
																			else {
																				if( ContainsString( smb_str_lo, "windows xp 5.2" ) && ContainsString( os_str_lo, "service pack 2" ) ){
																					os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_xp:-:sp2:x64", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																				}
																				else {
																					if( ContainsString( smb_str_lo, "windows xp 5.2" ) ){
																						os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_xp:-:-:x64", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																					}
																					else {
																						if( ContainsString( os_str_lo, "windows vista" ) && ContainsString( os_str_lo, "service pack 1" ) ){
																							os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_vista:-:sp1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																						}
																						else {
																							if( ContainsString( os_str_lo, "windows vista" ) && ContainsString( os_str_lo, "service pack 2" ) ){
																								os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_vista:-:sp2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																							}
																							else {
																								if( ContainsString( os_str_lo, "windows vista " ) ){
																									os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_vista", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																								}
																								else {
																									if( ContainsString( os_str_lo, "windows 7 " ) && ( ContainsString( os_str_lo, "service pack 1" ) || ContainsString( os_str, "7601" ) ) ){
																										os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_7:-:sp1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																									}
																									else {
																										if( ContainsString( os_str_lo, "windows 7 " ) && ContainsString( os_str, "7600" ) ){
																											os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_7:-:-:", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																										}
																										else {
																											if( ContainsString( os_str_lo, "windows 7 " ) ){
																												os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_7", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																											}
																											else {
																												if( ContainsString( os_str_lo, "windows 8.1 " ) ){
																													os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_8.1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																												}
																												else {
																													if( ContainsString( os_str_lo, "windows 8 " ) ){
																														os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_8", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																													}
																													else {
																														if( ContainsString( os_str_lo, "windows server 2003 " ) && ContainsString( os_str_lo, "service pack 1" ) ){
																															os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2003:-:sp1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																														}
																														else {
																															if( ContainsString( os_str_lo, "windows server 2003 " ) && ContainsString( os_str_lo, "service pack 2" ) ){
																																os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2003:-:sp2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																															}
																															else {
																																if( ContainsString( os_str_lo, "windows server 2003 " ) ){
																																	os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																}
																																else {
																																	if( ContainsString( os_str_lo, "windows server 2008 " ) && ContainsString( os_str_lo, "service pack 1" ) && ContainsString( os_str_lo, "r2" ) ){
																																		os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2008:r2:sp1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																	}
																																	else {
																																		if( ContainsString( os_str_lo, "windows server 2008 " ) && ContainsString( os_str_lo, "r2" ) ){
																																			os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2008:r2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																		}
																																		else {
																																			if( ContainsString( os_str_lo, "windows server (r) 2008 " ) && ContainsString( os_str_lo, "service pack 2" ) ){
																																				os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2008:-:sp2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																			}
																																			else {
																																				if( ContainsString( os_str_lo, "windows server (r) 2008 " ) && ContainsString( os_str_lo, "service pack 1" ) ){
																																					os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2008:-:sp1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																				}
																																				else {
																																					if( ContainsString( os_str_lo, "windows server (r) 2008 " ) || ContainsString( os_str_lo, "windows server 2008 " ) ){
																																						os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2008", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																					}
																																					else {
																																						if( ContainsString( os_str_lo, "windows server 2012 " ) ){
																																							os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2012", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																						}
																																						else {
																																							if( ContainsString( os_str_lo, "windows server 2016 " ) ){
																																								os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows_server_2016", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																																							}
																																							else {
																																								os_register_unknown_banner( banner: banner, banner_type_name: SCRIPT_DESC, port: port, banner_type_short: "smb_nativelanman_banner" );
																																								os_register_and_report( os: os_str, cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
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
														else {
															os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "smb_samba_banner", port: port );
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
				set_kb_item( name: "Host/OS/smb", value: os_str );
				set_kb_item( name: "SMB/OS", value: os_str );
				info = "Detected OS: " + os_str + "\n";
				result += info;
				report = TRUE;
			}
			if(report_verbosity && report){
				log_message( port: port, data: result );
			}
		}
		out = NULL;
	}
	else {
		out = s[x - 1] + s[x] + out;
	}
}
if(banner){
	banner = ereg_replace( string: banner, pattern: "^([\n\r ]+)", replace: "" );
	set_kb_item( name: "smb/native_lanman/full_banner", value: TRUE );
	set_kb_item( name: "smb/native_lanman/" + port + "/full_banner", value: chomp( banner ) );
}
exit( 0 );

