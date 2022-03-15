func hotfix_check_sp( nt, win2k, xp, xpx64, win2003, win2003x64, winVista, winVistax64, win7, win7x64, win2008, win2008x64, win2008r2, win8, win8x64, win2012, win2012R2, win8_1, win8_1x64, win10, win10x64, win2016, win2019 ){
	var winVer, winName, arch, SvPk;
	winVer = get_kb_item( "SMB/WindowsVersion" );
	winName = get_kb_item( "SMB/WindowsName" );
	arch = get_kb_item( "SMB/Windows/Arch" );
	if(!winVer){
		return -1;
	}
	if( nt && ( ContainsString( winVer, "4.0" ) ) ){
		SvPk = get_kb_item( "SMB/WinNT4/ServicePack" );
		if( SvPk ){
			SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
		}
		else {
			SvPk = 0;
		}
		if( SvPk < nt ){
			return 1;
		}
		else {
			return 0;
		}
	}
	else {
		if( win2k && ( ContainsString( winVer, "5.0" ) ) && ( ContainsString( winName, "Microsoft Windows 2000" ) ) ){
			SvPk = get_kb_item( "SMB/Win2K/ServicePack" );
			if( SvPk ){
				SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
			}
			else {
				SvPk = 0;
			}
			if( SvPk < win2k ){
				return 1;
			}
			else {
				return 0;
			}
		}
		else {
			if( xp && ( ContainsString( winVer, "5.1" ) ) && ( ContainsString( winName, "Microsoft Windows XP" ) ) ){
				SvPk = get_kb_item( "SMB/WinXP/ServicePack" );
				if( SvPk ){
					SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
				}
				else {
					SvPk = 0;
				}
				if( SvPk < xp ){
					return 1;
				}
				else {
					return 0;
				}
			}
			else {
				if( xpx64 && ( ContainsString( winVer, "5.2" ) ) && ( ContainsString( winName, "Microsoft Windows XP" ) ) && ( arch == "x64" ) ){
					SvPk = get_kb_item( "SMB/WinXPx64/ServicePack" );
					if( SvPk ){
						SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
					}
					else {
						SvPk = 0;
					}
					if( SvPk < xpx64 ){
						return 1;
					}
					else {
						return 0;
					}
				}
				else {
					if( win2003 && ( ContainsString( winVer, "5.2" ) ) && ( ContainsString( winName, "Microsoft Windows Server 2003" ) ) && ( arch == "x86" ) ){
						SvPk = get_kb_item( "SMB/Win2003/ServicePack" );
						if( SvPk ){
							SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
						}
						else {
							SvPk = 0;
						}
						if( SvPk < win2003 ){
							return 1;
						}
						else {
							return 0;
						}
					}
					else {
						if( win2003x64 && ( ContainsString( winVer, "5.2" ) ) && ( ContainsString( winName, "Microsoft Windows Server 2003" ) ) && ( arch == "x64" ) ){
							SvPk = get_kb_item( "SMB/Win2003x64/ServicePack" );
							if( SvPk ){
								SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
							}
							else {
								SvPk = 0;
							}
							if( SvPk < win2003x64 ){
								return 1;
							}
							else {
								return 0;
							}
						}
						else {
							if( winVista && ( ContainsString( winVer, "6.0" ) ) && ( ContainsString( winName, "Windows Vista" ) ) && ( arch == "x86" ) ){
								SvPk = get_kb_item( "SMB/WinVista/ServicePack" );
								if( SvPk ){
									SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
								}
								else {
									SvPk = 0;
								}
								if( SvPk < winVista ){
									return 1;
								}
								else {
									return 0;
								}
							}
							else {
								if( winVistax64 && ( ContainsString( winVer, "6.0" ) ) && ( ContainsString( winName, "Windows Vista" ) ) && ( arch == "x64" ) ){
									SvPk = get_kb_item( "SMB/WinVistax64/ServicePack" );
									if( SvPk ){
										SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
									}
									else {
										SvPk = 0;
									}
									if( SvPk < winVistax64 ){
										return 1;
									}
									else {
										return 0;
									}
								}
								else {
									if( win7 && ( ContainsString( winVer, "6.1" ) ) && ( ContainsString( winName, "Windows 7" ) ) && ( arch == "x86" ) ){
										SvPk = get_kb_item( "SMB/Win7/ServicePack" );
										if( SvPk ){
											SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
										}
										else {
											SvPk = 0;
										}
										if( SvPk < win7 ){
											return 1;
										}
										else {
											return 0;
										}
									}
									else {
										if( win7x64 && ( ContainsString( winVer, "6.1" ) ) && ( ContainsString( winName, "Windows 7" ) ) && ( arch == "x64" ) ){
											SvPk = get_kb_item( "SMB/Win7x64/ServicePack" );
											if( SvPk ){
												SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
											}
											else {
												SvPk = 0;
											}
											if( SvPk < win7x64 ){
												return 1;
											}
											else {
												return 0;
											}
										}
										else {
											if( win2008 && ( ContainsString( winVer, "6.0" ) ) && ( ContainsString( winName, "Windows Server (R) 2008" ) ) && ( arch == "x86" ) ){
												SvPk = get_kb_item( "SMB/Win2008/ServicePack" );
												if( SvPk ){
													SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
												}
												else {
													SvPk = 0;
												}
												if( SvPk < win2008 ){
													return 1;
												}
												else {
													return 0;
												}
											}
											else {
												if( win2008x64 && ( ContainsString( winVer, "6.0" ) ) && ( ContainsString( winName, "Windows Server (R) 2008" ) ) && ( arch == "x64" ) ){
													SvPk = get_kb_item( "SMB/Win2008x64/ServicePack" );
													if( SvPk ){
														SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
													}
													else {
														SvPk = 0;
													}
													if( SvPk < win2008x64 ){
														return 1;
													}
													else {
														return 0;
													}
												}
												else {
													if( win2008r2 && ( ContainsString( winVer, "6.1" ) ) && ( ContainsString( winName, "Windows Server 2008 R2" ) ) && ( arch == "x64" ) ){
														SvPk = get_kb_item( "SMB/Win2008R2/ServicePack" );
														if( SvPk ){
															SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
														}
														else {
															SvPk = 0;
														}
														if( SvPk < win2008r2 ){
															return 1;
														}
														else {
															return 0;
														}
													}
													else {
														if( win8 && ( ContainsString( winVer, "6.2" ) ) && ( ContainsString( winName, "Windows 8" ) ) && ( arch == "x86" ) ){
															SvPk = get_kb_item( "SMB/Win8/ServicePack" );
															if( SvPk ){
																SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
															}
															else {
																SvPk = 0;
															}
															if( SvPk < win8 ){
																return 1;
															}
															else {
																return 0;
															}
														}
														else {
															if( win8x64 && ( ContainsString( winVer, "6.2" ) ) && ( ContainsString( winName, "Windows 8" ) ) && ( arch == "x64" ) ){
																SvPk = get_kb_item( "SMB/Win8x64/ServicePack" );
																if( SvPk ){
																	SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																}
																else {
																	SvPk = 0;
																}
																if( SvPk < win8x64 ){
																	return 1;
																}
																else {
																	return 0;
																}
															}
															else {
																if( win2012 && ( ContainsString( winVer, "6.2" ) ) && ( ContainsString( winName, "Windows Server 2012" ) ) && ( arch == "x64" ) ){
																	SvPk = get_kb_item( "SMB/Win2012/ServicePack" );
																	if( SvPk ){
																		SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																	}
																	else {
																		SvPk = 0;
																	}
																	if( SvPk < win2012 ){
																		return 1;
																	}
																	else {
																		return 0;
																	}
																}
																else {
																	if( win2012R2 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows Server 2012 R2" ) ) && ( arch == "x64" ) ){
																		SvPk = get_kb_item( "SMB/Win2012R2/ServicePack" );
																		if( SvPk ){
																			SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																		}
																		else {
																			SvPk = 0;
																		}
																		if( SvPk < win2012R2 ){
																			return 1;
																		}
																		else {
																			return 0;
																		}
																	}
																	else {
																		if( win8_1 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows 8.1" ) ) && ( arch == "x86" ) ){
																			SvPk = get_kb_item( "SMB/Win8.1/ServicePack" );
																			if( SvPk ){
																				SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																			}
																			else {
																				SvPk = 0;
																			}
																			if( SvPk < win8_1 ){
																				return 1;
																			}
																			else {
																				return 0;
																			}
																		}
																		else {
																			if( win8_1x64 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows 8.1" ) ) && ( arch == "x64" ) ){
																				SvPk = get_kb_item( "SMB/Win8.1x64/ServicePack" );
																				if( SvPk ){
																					SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																				}
																				else {
																					SvPk = 0;
																				}
																				if( SvPk < win8_1x64 ){
																					return 1;
																				}
																				else {
																					return 0;
																				}
																			}
																			else {
																				if( win10 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows 10" ) ) && ( arch == "x86" ) ){
																					SvPk = get_kb_item( "SMB/Win10/ServicePack" );
																					if( SvPk ){
																						SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																					}
																					else {
																						SvPk = 0;
																					}
																					if( SvPk < win10 ){
																						return 1;
																					}
																					else {
																						return 0;
																					}
																				}
																				else {
																					if( win10x64 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows 10" ) ) && ( arch == "x64" ) ){
																						SvPk = get_kb_item( "SMB/Win10x64/ServicePack" );
																						if( SvPk ){
																							SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																						}
																						else {
																							SvPk = 0;
																						}
																						if( SvPk < win10x64 ){
																							return 1;
																						}
																						else {
																							return 0;
																						}
																					}
																					else {
																						if( win2016 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows Server 2016" ) ) && ( arch == "x64" ) ){
																							SvPk = get_kb_item( "SMB/Win2016/ServicePack" );
																							if( SvPk ){
																								SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																							}
																							else {
																								SvPk = 0;
																							}
																							if( SvPk < win2016 ){
																								return 1;
																							}
																							else {
																								return 0;
																							}
																						}
																						else {
																							if(win2019 && ( ContainsString( winVer, "6.3" ) ) && ( ContainsString( winName, "Windows Server 2019" ) ) && ( arch == "x64" )){
																								SvPk = get_kb_item( "SMB/Win2019/ServicePack" );
																								if( SvPk ){
																									SvPk = int( ereg_replace( string: SvPk, replace: "\\1", pattern: ".*Service Pack ([0-9]).*" ) );
																								}
																								else {
																									SvPk = 0;
																								}
																								if( SvPk < win2019 ){
																									return 1;
																								}
																								else {
																									return 0;
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
	return -1;
}
func hotfix_missing( name ){
	var name;
	var KB, _key;
	if(!name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#name#-#hotfix_missing" );
		return -1;
	}
	KB = get_kb_list( "SMB/Registry/HKLM/SOFTWARE/Microsoft/*" );
	if(isnull( KB ) || max_index( make_list( keys( KB ) ) ) == 0){
		return -1;
	}
	if( ContainsString( name, "KB" ) ){
		name -= "KB";
	}
	else {
		if( ContainsString( name, "Q" ) ){
			name -= "Q";
		}
		else {
			if(ContainsString( name, "M" )){
				name -= "M";
			}
		}
	}
	for _key in keys( KB ) {
		if( ereg( pattern: "SMB/Registry/HKLM/SOFTWARE/Microsoft/(Updates/.*|Windows NT/CurrentVersion/HotFix)/(KB|Q|M)" + name, string: _key ) ){
			return 0;
		}
		else {
			if(ereg( pattern: "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages/[P|p]ackage.?[0-9]*.?for.?KB.*" + name, string: _key )){
				return 0;
			}
		}
	}
	return 1;
}
func hotfix_check_domain_controler(  ){
	var product_options;
	product_options = get_kb_item( "SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions" );
	if( !product_options ) {
		return -1;
	}
	else {
		if( ContainsString( product_options, "LanmanNT" ) ) {
			return 1;
		}
		else {
			return 0;
		}
	}
}
func hotfix_check_nt_server(  ){
	var product_options;
	product_options = get_kb_item( "SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions" );
	if( !product_options ) {
		return -1;
	}
	else {
		if( ContainsString( product_options, "WinNT" ) ) {
			return 0;
		}
		else {
			return 1;
		}
	}
}
func hotfix_check_exchange_installed(  ){
	var vers;
	vers = get_kb_item( "SMB/Registry/HKLM/SOFTWARE/Microsoft/Exchange/Setup/ServicePackBuild" );
	if( !vers ) {
		return NULL;
	}
	else {
		return vers;
	}
}
func hotfix_check_iis_installed(  ){
	var w3svc;
	w3svc = get_kb_item( "SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath" );
	if( !w3svc ) {
		return -1;
	}
	else {
		if( !ContainsString( w3svc, "inetinfo" ) ) {
			return 0;
		}
		else {
			return 1;
		}
	}
}

