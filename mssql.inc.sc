func mssql_get_rel_name( version ){
	var version;
	if( IsMatchRegexp( version, "^1\\.0" ) ){
		return "1.0";
	}
	else {
		if( IsMatchRegexp( version, "^1\\.1" ) ){
			return "1.1";
		}
		else {
			if( IsMatchRegexp( version, "^4\\.2" ) ){
				return "4.2";
			}
			else {
				if( IsMatchRegexp( version, "^6\\.0" ) ){
					return "6.0";
				}
				else {
					if( IsMatchRegexp( version, "^6\\.5" ) ){
						if( IsMatchRegexp( version, "^6\\.5\\.201\\." ) ){
							return "6.5";
						}
						else {
							if( IsMatchRegexp( version, "^6\\.5\\.213" ) ){
								return "6.5 SP1";
							}
							else {
								if( IsMatchRegexp( version, "^6\\.5\\.240" ) ){
									return "6.5 SP2";
								}
								else {
									if( IsMatchRegexp( version, "^6\\.5\\.258" ) ){
										return "6.5 SP3";
									}
									else {
										if( IsMatchRegexp( version, "^6\\.5\\.281" ) ){
											return "6.5 SP4";
										}
										else {
											if( IsMatchRegexp( version, "^6\\.5\\.415" ) ){
												return "6.5 SP5";
											}
											else {
												if( IsMatchRegexp( version, "^6\\.5\\.416" ) ){
													return "6.5 SP5a";
												}
												else {
													return "6.5";
												}
											}
										}
									}
								}
							}
						}
					}
					else {
						if( IsMatchRegexp( version, "^7\\.0" ) ){
							if( IsMatchRegexp( version, "^7\\.0\\.623" ) ){
								return "7.0";
							}
							else {
								if( IsMatchRegexp( version, "^7\\.0\\.699" ) ){
									return "7.0 SP1";
								}
								else {
									if( IsMatchRegexp( version, "^7\\.0\\.842" ) ){
										return "7.0 SP2";
									}
									else {
										if( IsMatchRegexp( version, "^7\\.0\\.961" ) ){
											return "7.0 SP3";
										}
										else {
											if( IsMatchRegexp( version, "^7\\.0\\.1063" ) ){
												return "7.0 SP4";
											}
											else {
												return "7.0";
											}
										}
									}
								}
							}
						}
						else {
							if( IsMatchRegexp( version, "^8\\.0" ) ){
								if( IsMatchRegexp( version, "^8\\.0\\.194" ) ){
									return "2000";
								}
								else {
									if( IsMatchRegexp( version, "^8\\.0\\.384" ) ){
										return "2000 SP1";
									}
									else {
										if( IsMatchRegexp( version, "^8\\.0\\.53[24]" ) ){
											return "2000 SP2";
										}
										else {
											if( IsMatchRegexp( version, "^8\\.0\\.760" ) ){
												return "2000 SP3";
											}
											else {
												if( IsMatchRegexp( version, "^8\\.0\\.766" ) ){
													return "2000 SP3a";
												}
												else {
													if( IsMatchRegexp( version, "^8\\.0\\.2039" ) ){
														return "2000 SP4";
													}
													else {
														return "2000";
													}
												}
											}
										}
									}
								}
							}
							else {
								if( IsMatchRegexp( version, "^9\\.0" ) ){
									if( IsMatchRegexp( version, "^9\\.0\\.1399" ) ){
										return "2005";
									}
									else {
										if( IsMatchRegexp( version, "^9\\.0\\.2047" ) ){
											return "2005 SP1";
										}
										else {
											if( IsMatchRegexp( version, "^9\\.0\\.3042" ) ){
												return "2005 SP2";
											}
											else {
												if( IsMatchRegexp( version, "^9\\.0\\.4035" ) ){
													return "2005 SP3";
												}
												else {
													if( IsMatchRegexp( version, "^9\\.0\\.5[0-9]{3}" ) ){
														return "2005 SP4";
													}
													else {
														return "2005";
													}
												}
											}
										}
									}
								}
								else {
									if( IsMatchRegexp( version, "^10\\.0" ) ){
										if( IsMatchRegexp( version, "^10\\.0\\.1600" ) ){
											return "2008";
										}
										else {
											if( IsMatchRegexp( version, "^10\\.0\\.2531" ) ){
												return "2008 SP1";
											}
											else {
												if( IsMatchRegexp( version, "^10\\.0\\.4[0-9]{3}" ) ){
													return "2008 SP2";
												}
												else {
													if( IsMatchRegexp( version, "^10\\.0\\.55[0-9]{2}" ) ){
														return "2008 SP3";
													}
													else {
														if( IsMatchRegexp( version, "^10\\.0\\.6[0-9]{3}" ) ){
															return "2008 SP4";
														}
														else {
															return "2008";
														}
													}
												}
											}
										}
									}
									else {
										if( IsMatchRegexp( version, "^10\\.50" ) ){
											if( IsMatchRegexp( version, "^10\\.50\\.1600" ) ){
												return "2008 R2";
											}
											else {
												if( IsMatchRegexp( version, "^10\\.50\\.25[0-9]{2}" ) ){
													return "2008 R2 SP1";
												}
												else {
													if( IsMatchRegexp( version, "^10\\.50\\.4[0-9]{3}" ) ){
														return "2008 R2 SP2";
													}
													else {
														if( IsMatchRegexp( version, "^10\\.50\\.6[0-9]{3}" ) ){
															return "2008 R2 SP3";
														}
														else {
															return "2008 R2";
														}
													}
												}
											}
										}
										else {
											if( IsMatchRegexp( version, "^11\\.0" ) ){
												if( IsMatchRegexp( version, "^11\\.0\\.3[0-9]{3}" ) ){
													return "2012 SP1";
												}
												else {
													if( IsMatchRegexp( version, "^11\\.0\\.5[0-9]{3}" ) ){
														return "2012 SP2";
													}
													else {
														if( IsMatchRegexp( version, "^11\\.0\\.6[0-9]{3}" ) ){
															return "2012 SP3";
														}
														else {
															if( IsMatchRegexp( version, "^11\\.0\\.7[0-9]{3}" ) ){
																return "2012 SP4";
															}
															else {
																return "2012";
															}
														}
													}
												}
											}
											else {
												if( IsMatchRegexp( version, "^12\\.0" ) ){
													if( IsMatchRegexp( version, "^12\\.0\\.4[0-9]{3}" ) ){
														return "2014 SP1";
													}
													else {
														if( IsMatchRegexp( version, "^12\\.0\\.5[0-9]{3}" ) ){
															return "2014 SP2";
														}
														else {
															if( IsMatchRegexp( version, "^12\\.0\\.6[0-9]{3}" ) ){
																return "2014 SP3";
															}
															else {
																return "2014";
															}
														}
													}
												}
												else {
													if( IsMatchRegexp( version, "^13\\.0" ) ){
														if( IsMatchRegexp( version, "^13\\.0\\.4[0-9]{3}" ) ){
															return "2016 SP1";
														}
														else {
															if( IsMatchRegexp( version, "^13\\.0\\.5[0-9]{3}" ) ){
																return "2016 SP2";
															}
															else {
																return "2016";
															}
														}
													}
													else {
														if( IsMatchRegexp( version, "^14\\.0" ) ){
															return "2017";
														}
														else {
															if( IsMatchRegexp( version, "^15\\.0" ) ){
																return "2019";
															}
															else {
																return "unknown release name";
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

