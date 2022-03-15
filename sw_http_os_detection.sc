if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111067" );
	script_version( "2021-09-15T13:28:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:28:54 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-12-10 16:00:00 +0100 (Thu, 10 Dec 2015)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc", "sw_apcu_info.sc", "gb_phpinfo_output_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based OS detection from the HTTP/PHP banner or default test pages." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (HTTP)";
func check_http_banner( port, banner ){
	var port, banner, banner_type, version;
	banner = chomp( banner );
	if(!banner){
		return;
	}
	if(_banner = egrep( string: banner, pattern: "^X-spinetix-(firmware|serial|hw)\\s*:", icase: TRUE )){
		os_register_and_report( os: "SpinetiX Digital Signage Unknown Model Player Firmware", cpe: "cpe:/o:spinetix:unknown_model_firmware", banner_type: banner_type, port: port, banner: chomp( _banner ), desc: SCRIPT_DESC, runs_key: "unixoide" );
		return;
	}
	if(banner = egrep( pattern: "^Server\\s*:.*$", string: banner, icase: TRUE )){
		banner = chomp( banner );
		if(IsMatchRegexp( banner, "^Server\\s*:\\s*(Oracle-iPlanet-Web(-Proxy)?-Server|Sun-Java-System-Web-Server|Sun-ONE-Web-Server)(/[0-9.]+)?$" )){
			return;
		}
		if(IsMatchRegexp( banner, "^Server\\s*:\\s*AirTunes(/[0-9.]+)?$" )){
			return;
		}
		if(ContainsString( banner, "Server: uIP/" )){
			return;
		}
		if(ContainsString( banner, "Server: FNET HTTP" )){
			return;
		}
		if(ContainsString( banner, "Server:ENIServer" )){
			return;
		}
		if(ContainsString( banner, "Server: WebLogic" )){
			return;
		}
		if(ContainsString( banner, "WIBU-SYSTEMS HTTP Server" )){
			return;
		}
		if(banner == "Server: Spark"){
			return;
		}
		if(banner == "Server: Lotus-Domino" || banner == "Server: Lotus Domino"){
			return;
		}
		if(banner == "Server: BigIP"){
			return;
		}
		if(banner == "Server: aMule"){
			return;
		}
		if(banner == "Server: Transmission"){
			return;
		}
		if(banner == "Server: Logitech Media Server" || egrep( pattern: "^Server: Logitech Media Server \\([0-9.]+\\)$", string: banner ) || egrep( pattern: "^Server: Logitech Media Server \\([0-9.]+ - [0-9.]+\\)$", string: banner )){
			return;
		}
		if(ContainsString( banner, "Server: nzbget" )){
			return;
		}
		if(ContainsString( banner, "Server: Icinga" )){
			return;
		}
		if(ContainsString( banner, "Kerio Connect" ) || ContainsString( banner, "Kerio MailServer" )){
			return;
		}
		if(ContainsString( banner, "SentinelProtectionServer" ) || ContainsString( banner, "SentinelKeysServer" )){
			return;
		}
		if(egrep( pattern: "^Server: EWS-NIC5/[0-9.]+$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: CTCFC/[0-9.]+$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: SimpleHTTP/[0-9.]+ Python/[0-9.]+$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: Python/[0-9.]+ aiohttp/[0-9.]+$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: BaseHTTP/[0-9.]+ Python/[0-9.]+(rc[0-9]+|\\+)?$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: MX4J-HTTPD/[0-9.]+$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: libwebsockets$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server: mt-daapd/?([0-9.]+|svn-[0-9]+)?$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server: Mongoose/?[0-9.]*$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server: WSO2 Carbon Server", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: ELOG HTTP", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: openresty/?[0-9.]*$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server: AppManager", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^server\\s*:\\s*SAP NetWeaver Application Server", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*WEBrick/([0-9.]+)(\\s*\\(Ruby/([0-9.]+)[^\\)]+\\))?(\\s*OpenSSL/([0-9a-z.]+))?$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*Cherokee(/[0-9.]+)?$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*lwIP", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server: SAP Internet Graphics Server", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*(Light Weight Web Server|Embedded HTTP Server\\.)$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*Apache TomEE", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*Chunjs/Server", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*HyperX/[0-9.]+ \\(\\s*ThreadX\\s*\\)$", string: banner, icase: TRUE )){
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*eHTTP\\s*v2\\.0$", string: banner, icase: TRUE )){
			return;
		}
		if(banner == "Server:" || banner == "Server: " || banner == "Server: /" || banner == "Server: server" || banner == "Server: Undefined" || banner == "Server: WebServer" || banner == "Server: squid" || banner == "Server: nginx" || banner == "Server: Apache" || banner == "Server: lighttpd" || banner == "Server: sfcHttpd" || banner == "Server: Web" || banner == "Server: Allegro-Software-RomPager" || banner == "Server: Apache-Coyote/1.0" || banner == "Server: Apache-Coyote/1.1" || banner == "Server: HASP LM" || banner == "Server: Mbedthis-Appweb" || banner == "Server: Embedthis-Appweb" || banner == "Server: Embedthis-http" || banner == "Server: GoAhead-Webs" || banner == "Server: Mojolicious (Perl)" || banner == "Server: Java/0.0" || banner == "Server: NessusWWW" || banner == "Server: Embedded Web Server" || banner == "Server: EZproxy" || banner == "Server: com.novell.zenworks.httpserver" || ContainsString( banner, "erver: BBC " ) || ContainsString( banner, "Server: PanWeb Server/" ) || egrep( pattern: "^Server: com.novell.zenworks.httpserver/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: DHost/[0-9.]+ HttpStk/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Tomcat/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Themis [0-9.]+$", string: banner ) || egrep( pattern: "^Server: Mordac/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: eHTTP v[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Agranat-EmWeb/[0-9_R]+$" ) || egrep( pattern: "^Server: gSOAP/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: squid/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: squid/[0-9.]+\\.STABLE[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Jetty\\([0-9.v]+\\)$", string: banner ) || egrep( pattern: "^Server: Jetty\\([0-9.]+z-SNAPSHOT\\)$", string: banner ) || egrep( pattern: "^Server: Jetty\\(winstone-[0-9.]+\\)$", string: banner ) || egrep( pattern: "^Server: nginx/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Apache/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: lighttpd/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: CompaqHTTPServer/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: http server [0-9.]+$", string: banner ) || egrep( pattern: "^Server: Web Server [0-9.]+$", string: banner ) || egrep( pattern: "^Server: Web Server$", string: banner ) || egrep( pattern: "^Server: MiniServ/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: RealVNC/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: HASP LM/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Mbedthis-Appweb/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Embedthis-http/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Embedthis-Appweb/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: GoAhead-Webs/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Allegro-Software-RomPager/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: CompaqHTTPServer/[0-9.]+ HPE System Management Homepage$", string: banner ) || egrep( pattern: "^Server: CompaqHTTPServer/[0-9.]+ HP System Management Homepage/[0-9.]+$", string: banner ) || egrep( pattern: "^Server: Payara Server +[0-9.]+ #badassfish$", string: banner )){
			return;
		}
		if(egrep( pattern: "^Server: Apache/[0-9.]+ \\(\\)(( (mod_auth_gssapi|mod_nss|NSS|mod_wsgi|Python)/[0-9.]+)*)?$", string: banner, icase: TRUE )){
			return;
		}
		banner_type = "HTTP Server banner";
		if(egrep( pattern: "^SERVER: Ubuntu", string: banner, icase: TRUE )){
			version = eregmatch( pattern: "SERVER: Ubuntu/([0-9.]+)", string: banner, icase: TRUE );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Ubuntu", version: version[1], cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "Ubuntu/warty" ) ){
					os_register_and_report( os: "Ubuntu", version: "4.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "Ubuntu/hoary" ) ){
						os_register_and_report( os: "Ubuntu", version: "5.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "Ubuntu/breezy" ) ){
							os_register_and_report( os: "Ubuntu", version: "5.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "Ubuntu/dapper" ) ){
								os_register_and_report( os: "Ubuntu", version: "6.06", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( banner, "Ubuntu/edgy" ) ){
									os_register_and_report( os: "Ubuntu", version: "6.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( banner, "Ubuntu/feisty" ) ){
										os_register_and_report( os: "Ubuntu", version: "7.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( banner, "Ubuntu/gutsy" ) ){
											os_register_and_report( os: "Ubuntu", version: "7.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( banner, "Ubuntu/hardy" ) ){
												os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( banner, "Ubuntu/intrepid" ) ){
													os_register_and_report( os: "Ubuntu", version: "8.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													if( ContainsString( banner, "Ubuntu/jaunty" ) ){
														os_register_and_report( os: "Ubuntu", version: "9.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													}
													else {
														if( ContainsString( banner, "Ubuntu/karmic" ) ){
															os_register_and_report( os: "Ubuntu", version: "9.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
														else {
															if( ContainsString( banner, "Ubuntu/lucid" ) ){
																os_register_and_report( os: "Ubuntu", version: "10.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
															else {
																if( ContainsString( banner, "Ubuntu/maverick" ) ){
																	os_register_and_report( os: "Ubuntu", version: "10.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	if( ContainsString( banner, "Ubuntu/natty" ) ){
																		os_register_and_report( os: "Ubuntu", version: "11.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	}
																	else {
																		if( ContainsString( banner, "Ubuntu/oneiric" ) ){
																			os_register_and_report( os: "Ubuntu", version: "11.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		}
																		else {
																			if( ContainsString( banner, "Ubuntu/precise" ) ){
																				os_register_and_report( os: "Ubuntu", version: "12.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			}
																			else {
																				if( ContainsString( banner, "Ubuntu/quantal" ) ){
																					os_register_and_report( os: "Ubuntu", version: "12.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																				}
																				else {
																					if( ContainsString( banner, "Ubuntu/raring" ) ){
																						os_register_and_report( os: "Ubuntu", version: "13.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																					}
																					else {
																						if( ContainsString( banner, "Ubuntu/saucy" ) ){
																							os_register_and_report( os: "Ubuntu", version: "13.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																						}
																						else {
																							if( ContainsString( banner, "Ubuntu/trusty" ) ){
																								os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																							}
																							else {
																								if( ContainsString( banner, "Ubuntu/utopic" ) ){
																									os_register_and_report( os: "Ubuntu", version: "14.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																								}
																								else {
																									if( ContainsString( banner, "Ubuntu/vivid" ) ){
																										os_register_and_report( os: "Ubuntu", version: "15.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																									}
																									else {
																										if( ContainsString( banner, "Ubuntu/wily" ) ){
																											os_register_and_report( os: "Ubuntu", version: "15.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																										}
																										else {
																											if( ContainsString( banner, "Ubuntu/xenial" ) ){
																												os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																											}
																											else {
																												if( ContainsString( banner, "Ubuntu/yakkety" ) ){
																													os_register_and_report( os: "Ubuntu", version: "16.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																												}
																												else {
																													if( ContainsString( banner, "Ubuntu/zesty" ) ){
																														os_register_and_report( os: "Ubuntu", version: "17.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																													}
																													else {
																														if( ContainsString( banner, "Ubuntu/artful" ) ){
																															os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																														}
																														else {
																															if( ContainsString( banner, "Ubuntu/bionic" ) ){
																																os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																															}
																															else {
																																if( ContainsString( banner, "Ubuntu/cosmic" ) ){
																																	os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																}
																																else {
																																	if( ContainsString( banner, "Ubuntu/disco" ) ){
																																		os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																	}
																																	else {
																																		if( ContainsString( banner, "Ubuntu/eoan" ) ){
																																			os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																		}
																																		else {
																																			if( ContainsString( banner, "Ubuntu/focal" ) ){
																																				os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																			}
																																			else {
																																				os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
			return;
		}
		if(egrep( pattern: "^Server: Debian", string: banner, icase: TRUE )){
			version = eregmatch( pattern: "Server: Debian/([0-9.]+)", string: banner, icase: TRUE );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "Debian/buster" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "Debian/stretch" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "Debian/jessie" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "Debian/wheezy" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( banner, "Debian/squeeze" ) ){
									os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( banner, "Debian/lenny" ) ){
										os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( banner, "Debian/etch" ) ){
											os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( banner, "Debian/sarge" ) ){
												os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( banner, "Debian/woody" ) ){
													os_register_and_report( os: "Debian GNU/Linux", version: "3.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													if( ContainsString( banner, "Debian/potato" ) ){
														os_register_and_report( os: "Debian GNU/Linux", version: "2.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													}
													else {
														if( ContainsString( banner, "Debian/slink" ) ){
															os_register_and_report( os: "Debian GNU/Linux", version: "2.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														}
														else {
															if( ContainsString( banner, "Debian/hamm" ) ){
																os_register_and_report( os: "Debian GNU/Linux", version: "2.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															}
															else {
																if( ContainsString( banner, "Debian/bo" ) ){
																	os_register_and_report( os: "Debian GNU/Linux", version: "1.3", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																}
																else {
																	if( ContainsString( banner, "Debian/rex" ) ){
																		os_register_and_report( os: "Debian GNU/Linux", version: "1.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	}
																	else {
																		if( ContainsString( banner, "Debian/buzz" ) ){
																			os_register_and_report( os: "Debian GNU/Linux", version: "1.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		}
																		else {
																			os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
			return;
		}
		if(egrep( pattern: "^Server: CentOS", string: banner, icase: TRUE )){
			version = eregmatch( pattern: "Server: CentOS/([0-9.]+)", string: banner, icase: TRUE );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "CentOS", version: version[1], cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			return;
		}
		if(ContainsString( banner, "MS .NET Remoting" ) || ContainsString( banner, "MS .NET CLR" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(ContainsString( banner, "Server: cisco-IOS" )){
			os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Server: GoTTY" ) || ContainsString( banner, "Server: Boa" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Server: Mathopd" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Microsoft-WinCE" )){
			version = eregmatch( pattern: "Microsoft-WinCE/([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Microsoft Windows CE", version: version[1], cpe: "cpe:/o:microsoft:windows_ce", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			}
			else {
				os_register_and_report( os: "Microsoft Windows CE", cpe: "cpe:/o:microsoft:windows_ce", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			}
			return;
		}
		if(ContainsString( banner, "VxWorks" )){
			os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Server: OfficeScan Client" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(IsMatchRegexp( banner, "Server\\s*:\\s*(Microsoft-)?Cassini" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(IsMatchRegexp( banner, "SERVER\\s*:\\s*(UPnP/[0-9]\\.[0-9]\\s*)?Samsung AllShare Server" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(IsMatchRegexp( banner, "Server\\s*:\\s*ArGoSoft Mail Server" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(banner == "Server: CPWS"){
			os_register_and_report( os: "Check Point Gaia", cpe: "cpe:/o:checkpoint:gaia_os", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "MoxaHttp" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "NetApp" )){
			version = eregmatch( pattern: "NetApp//?([0-9a-zA-Z.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "NetApp Data ONTAP", version: version[1], cpe: "cpe:/o:netapp:data_ontap", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			return;
		}
		if(ContainsString( banner, "ManageUPSnet Web Server" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Jetty/" )){
			if(ContainsString( banner, "(Windows" )){
				if(ContainsString( banner, "(Windows Server 2016" )){
					os_register_and_report( os: "Microsoft Windows Server 2016", cpe: "cpe:/o:microsoft:windows_server_2016", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows 10" )){
					os_register_and_report( os: "Microsoft Windows 10", cpe: "cpe:/o:microsoft:windows_10", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows Server 2012 R2" )){
					os_register_and_report( os: "Microsoft Windows Server 2012 R2", cpe: "cpe:/o:microsoft:windows_server_2012:r2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows 8.1" )){
					os_register_and_report( os: "Microsoft Windows 8.1", cpe: "cpe:/o:microsoft:windows_8.1", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows Server 2012" )){
					os_register_and_report( os: "Microsoft Windows Server 2012", cpe: "cpe:/o:microsoft:windows_server_2012", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows 8" )){
					os_register_and_report( os: "Microsoft Windows 8", cpe: "cpe:/o:microsoft:windows_8", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows Server 2008 R2" )){
					os_register_and_report( os: "Microsoft Windows Server 2008 R2", cpe: "cpe:/o:microsoft:windows_server_2008:r2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows 7" )){
					os_register_and_report( os: "Microsoft Windows 7", cpe: "cpe:/o:microsoft:windows_7", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows Server 2008" )){
					os_register_and_report( os: "Microsoft Windows Server 2008", cpe: "cpe:/o:microsoft:windows_server_2008", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows Vista" ) && !ContainsString( banner, "Vista/6.1" ) && !ContainsString( banner, "Vista/6.2" )){
					os_register_and_report( os: "Microsoft Windows Vista", cpe: "cpe:/o:microsoft:windows_vista", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows Server 2003" ) || ContainsString( banner, "(Windows 2003" )){
					os_register_and_report( os: "Microsoft Windows Server 2003", cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows XP" )){
					os_register_and_report( os: "Microsoft Windows XP Professional", cpe: "cpe:/o:microsoft:windows_xp", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(ContainsString( banner, "(Windows 2000" ) && !ContainsString( banner, "2000/5.2" )){
					os_register_and_report( os: "Microsoft Windows 2000", cpe: "cpe:/o:microsoft:windows_2000", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if( !ContainsString( banner, "Vista" ) && !ContainsString( banner, "Windows 2000" ) ) {
					os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "http_banner", port: port );
				}
				else {
					banner += "\nNote: 6.2 and 6.1 version codes in the Vista Banner are actually no Windows Vista. Same is valid for Windows 2000 banners having 5.2 as the version code";
				}
				os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
				return;
			}
			if(ContainsString( banner, "(Linux" )){
				version = eregmatch( pattern: "\\(Linux/([0-9.]+)", string: banner );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Linux", version: version[1], cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				return;
			}
			if(ContainsString( banner, "(SunOS" )){
				version = eregmatch( pattern: "\\(SunOS(/| )([0-9.]+)", string: banner );
				if( !isnull( version[2] ) ){
					os_register_and_report( os: "SunOS", version: version[2], cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				return;
			}
		}
		if(ContainsString( banner, "HPE-iLO-Server" ) || ContainsString( banner, "HP-iLO-Server" )){
			os_register_and_report( os: "HP iLO", cpe: "cpe:/o:hp:integrated_lights-out", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "ACS [0-9.]+" )){
			os_register_and_report( os: "Cisco", cpe: "cpe:/o:cisco", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Microsoft-HTTPAPI" ) || ( ContainsString( banner, "Apache" ) && ( ContainsString( banner, "(Win32)" ) || ContainsString( banner, "(Win64)" ) ) )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(egrep( pattern: "^Server: RTC/[56]\\.0", string: banner )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(ContainsString( banner, "Microsoft-IIS" )){
			version = eregmatch( pattern: "Microsoft-IIS/([0-9.]+)", string: banner );
			if(!isnull( version[1] )){
				if(version[1] == "10.0"){
					os_register_and_report( os: "Microsoft Windows Server 2016 or Microsoft Windows 10", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "8.5"){
					os_register_and_report( os: "Microsoft Windows Server 2012 R2 or Microsoft Windows 8.1", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "8.0"){
					os_register_and_report( os: "Microsoft Windows Server 2012 or Microsoft Windows 8", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "7.5"){
					os_register_and_report( os: "Microsoft Windows Server 2008 R2 or Microsoft Windows 7", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "7.0"){
					os_register_and_report( os: "Microsoft Windows Server 2008 or Microsoft Windows Vista", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "6.0"){
					os_register_and_report( os: "Microsoft Windows Server 2003 R2", cpe: "cpe:/o:microsoft:windows_server_2003:r2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					os_register_and_report( os: "Microsoft Windows Server 2003", cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					os_register_and_report( os: "Microsoft Windows XP Professional x64", cpe: "cpe:/o:microsoft:windows_xp:-:-:x64", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "5.1"){
					os_register_and_report( os: "Microsoft Windows XP Professional", cpe: "cpe:/o:microsoft:windows_xp", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "5.0"){
					os_register_and_report( os: "Microsoft Windows 2000", cpe: "cpe:/o:microsoft:windows_2000", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "4.0"){
					os_register_and_report( os: "Microsoft Windows NT 4.0 Option Pack", cpe: "cpe:/o:microsoft:windows_nt:4.0", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "3.0"){
					os_register_and_report( os: "Microsoft Windows NT 4.0 SP2", cpe: "cpe:/o:microsoft:windows_nt:4.0:sp2", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "2.0"){
					os_register_and_report( os: "Microsoft Windows NT", version: "4.0", cpe: "cpe:/o:microsoft:windows_nt", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
				if(version[1] == "1.0"){
					os_register_and_report( os: "Microsoft Windows NT", version: "3.51", cpe: "cpe:/o:microsoft:windows_nt", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
					return;
				}
			}
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "http_banner", port: port );
			return;
		}
		if(ContainsString( banner, "(SunOS," ) || ContainsString( banner, "(SunOS)" )){
			os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "/NetBSD" )){
			os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "(FreeBSD)" ) || ContainsString( banner, "-freebsd-" )){
			os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "OpenBSD" )){
			os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Apache/" ) && ContainsString( banner, "Debian" )){
			if(ContainsString( banner, "Apache/1.3.9 (Unix) Debian/GNU" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "2.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/1.3.26 (Unix) Debian GNU/Linux" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "3.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/1.3.33 (Debian GNU/Linux)" ) || ContainsString( banner, "Apache/2.0.54 (Debian GNU/Linux)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/1.3.34 (Debian)" ) || ContainsString( banner, "Apache/2.2.3 (Debian)" ) || ( ContainsString( banner, "Apache/1.3.34 Ben-SSL" ) && ContainsString( banner, "(Debian)" ) )){
				os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/2.2.9 (Debian)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/2.2.16 (Debian)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/2.2.22 (Debian)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/2.4.10 (Debian)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/2.4.25 (Debian)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(ContainsString( banner, "Apache/2.4.38 (Debian)" )){
				os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
		}
		if(ContainsString( banner, "ZNC" ) && ( ContainsString( banner, "~bpo" ) || ContainsString( banner, "+deb" ) )){
			if( ContainsString( banner, "~bpo7" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "~bpo8" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "1.6.5+deb1" ) || ContainsString( banner, "~bpo9" ) || IsMatchRegexp( banner, "\\+deb[0-9]\\+deb9" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "1.7.2+deb3" ) || ContainsString( banner, "~bpo10" ) || IsMatchRegexp( banner, "\\+deb[0-9]\\+deb10" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
					}
				}
			}
			return;
		}
		if( IsMatchRegexp( banner, "[+\\-~.]bookworm" ) ){
			os_register_and_report( os: "Debian GNU/Linux", version: "12", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		else {
			if( IsMatchRegexp( banner, "[+\\-~.]bullseye" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "11", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			else {
				if( IsMatchRegexp( banner, "[+\\-~.]buster" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					return;
				}
				else {
					if( IsMatchRegexp( banner, "[+\\-~.]stretch" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						return;
					}
					else {
						if( IsMatchRegexp( banner, "[+\\-~.]jessie" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							return;
						}
						else {
							if( IsMatchRegexp( banner, "[+\\-~.]wheezy" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								return;
							}
							else {
								if( IsMatchRegexp( banner, "[+\\-~.]squeeze" ) ){
									os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									return;
								}
								else {
									if( IsMatchRegexp( banner, "[+\\-~.]lenny" ) ){
										os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										return;
									}
									else {
										if( IsMatchRegexp( banner, "[+\\-~.]etch" ) ){
											os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											return;
										}
										else {
											if( IsMatchRegexp( banner, "[+\\-~.]sarge" ) ){
												os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												return;
											}
											else {
												if( IsMatchRegexp( banner, "[+\\-~.]woody" ) ){
													os_register_and_report( os: "Debian GNU/Linux", version: "3.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													return;
												}
												else {
													if( IsMatchRegexp( banner, "[+\\-~.]potato" ) ){
														os_register_and_report( os: "Debian GNU/Linux", version: "2.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														return;
													}
													else {
														if( IsMatchRegexp( banner, "[+\\-~.]slink" ) ){
															os_register_and_report( os: "Debian GNU/Linux", version: "2.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															return;
														}
														else {
															if( IsMatchRegexp( banner, "[+\\-~.]hamm" ) ){
																os_register_and_report( os: "Debian GNU/Linux", version: "2.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																return;
															}
															else {
																if( IsMatchRegexp( banner, "[+\\-~.]bo[0-9 ]+" ) ){
																	os_register_and_report( os: "Debian GNU/Linux", version: "1.3", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	return;
																}
																else {
																	if( IsMatchRegexp( banner, "[+\\-~.]rex[0-9 ]+" ) ){
																		os_register_and_report( os: "Debian GNU/Linux", version: "1.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		return;
																	}
																	else {
																		if(IsMatchRegexp( banner, "[+\\-~.]buzz" )){
																			os_register_and_report( os: "Debian GNU/Linux", version: "1.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			return;
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
		if(IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)" )){
			if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(4|etch)" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(5|lenny)" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(6|squeeze)" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(7|wheezy)" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(8|jessie)" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(9|stretch)" ) ){
									os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(10|buster)" ) ){
										os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(11|bullseye)" ) ){
											os_register_and_report( os: "Debian GNU/Linux", version: "11", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( IsMatchRegexp( banner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(12|bookworm)" ) ){
												os_register_and_report( os: "Debian GNU/Linux", version: "12", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return;
		}
		if(IsMatchRegexp( banner, "\\(Debian\\)" ) || IsMatchRegexp( banner, "\\(Debian GNU/Linux\\)" ) || ContainsString( banner, "devel-debian" ) || ContainsString( banner, "~dotdeb+" ) || IsMatchRegexp( banner, "\\(Raspbian\\)" )){
			os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(Gentoo\\)" ) || IsMatchRegexp( banner, "\\(Gentoo Linux\\)" ) || ContainsString( banner, "-gentoo" )){
			os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(Linux/SUSE\\)" ) || IsMatchRegexp( banner, "/SuSE\\)" )){
			os_register_and_report( os: "SUSE Linux", cpe: "cpe:/o:novell:suse_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(Arch Linux\\)" )){
			os_register_and_report( os: "Arch Linux", cpe: "cpe:/o:archlinux:arch_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(CentOS\\)" )){
			if( ContainsString( banner, "Apache/2.4.37 (CentOS)" ) ){
				os_register_and_report( os: "CentOS", version: "8", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "Apache/2.4.6 (CentOS)" ) ){
					os_register_and_report( os: "CentOS", version: "7", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "Apache/2.2.15 (CentOS)" ) ){
						os_register_and_report( os: "CentOS", version: "6", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "Apache/2.2.3 (CentOS)" ) ){
							os_register_and_report( os: "CentOS", version: "5", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "Apache/2.0.52 (CentOS)" ) ){
								os_register_and_report( os: "CentOS", version: "4", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( banner, "Apache/2.0.46 (CentOS)" ) ){
									os_register_and_report( os: "CentOS", version: "3", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
							}
						}
					}
				}
			}
			return;
		}
		if(IsMatchRegexp( banner, "\\(Ubuntu\\)" ) || ( ContainsString( banner, "PHP/" ) && ContainsString( banner, "ubuntu" ) )){
			if( ContainsString( banner, "Apache/2.4.41 (Ubuntu)" ) ){
				os_register_and_report( os: "Ubuntu", version: "19.10 or 20.04", cpe: "cpe:/o:canonical:ubuntu_linux:20.04", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
			}
			else {
				if( ContainsString( banner, "ubuntu0.20.04" ) || ContainsString( banner, "nginx/1.17.10 (Ubuntu)" ) ){
					os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "ubuntu0.19.10" ) || ContainsString( banner, "nginx/1.16.1 (Ubuntu)" ) ){
						os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "Apache/2.4.38 (Ubuntu)" ) || ContainsString( banner, "ubuntu0.19.04" ) || ContainsString( banner, "nginx/1.15.9 (Ubuntu)" ) ){
							os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "Apache/2.4.34 (Ubuntu)" ) || ContainsString( banner, "PHP/7.2.10-0ubuntu1" ) || ContainsString( banner, "nginx/1.15.5 (Ubuntu)" ) ){
								os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( banner, "Apache/2.4.29 (Ubuntu)" ) || ContainsString( banner, "PHP/7.2.3-1ubuntu1" ) || ContainsString( banner, "nginx/1.14.0 (Ubuntu)" ) ){
									os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( banner, "Apache/2.2.8 (Ubuntu)" ) || ContainsString( banner, "PHP/5.2.4-2ubuntu5.10" ) ){
										os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( banner, "nginx/1.12.1 (Ubuntu)" ) ){
											os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( banner, "nginx/1.10.3 (Ubuntu)" ) ){
												os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( banner, "nginx/1.4.6 (Ubuntu)" ) ){
													os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
			return;
		}
		if(ContainsString( banner, "(Red Hat Enterprise Linux)" )){
			os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "(Red Hat)" ) || ContainsString( banner, "(Red-Hat/Linux)" )){
			if( ContainsString( banner, "Apache/1.3.23 (Unix)  (Red-Hat/Linux)" ) ){
				os_register_and_report( os: "CentOS", version: "2", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			return;
		}
		if(ContainsString( banner, "(Fedora)" )){
			os_register_and_report( os: "Fedora", cpe: "cpe:/o:fedoraproject:fedora", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "(Oracle)" )){
			os_register_and_report( os: "Oracle Linux", cpe: "cpe:/o:oracle:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(Unix\\)" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "mini-http" ) && ContainsString( banner, "(unix)" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "(Univention)" )){
			os_register_and_report( os: "Univention Corporate Server", cpe: "cpe:/o:univention:univention_corporate_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(Mandrake ?[Ll]inux" )){
			os_register_and_report( os: "Mandrake", cpe: "cpe:/o:mandrakesoft:mandrake_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Nginx on Linux Debian" )){
			os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Nginx centOS" )){
			os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Nginx (OpenBSD)" ) || ( ContainsString( banner, "Lighttpd" ) && ContainsString( banner, "OpenBSD" ) )){
			os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*pve-api-daemon", string: banner, icase: TRUE )){
			os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( tolower( banner ), "server: posix, upnp/1.0, intel microstack" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "^Server: .* Phusion[ _]Passenger" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Server: IceWarp" )){
			if( os_info = eregmatch( pattern: "Server: IceWarp( WebSrv)?/([0-9.]+) ([^ ]+) ([^ ]+)", string: banner, icase: FALSE ) ){
				if( ContainsString( os_info[3], "RHEL" ) ){
					version = eregmatch( pattern: "RHEL([0-9.]+)", string: os_info[3] );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					return;
				}
				else {
					if( ContainsString( os_info[3], "DEB" ) ){
						version = eregmatch( pattern: "DEB([0-9.]+)", string: os_info[3] );
						if( !isnull( version[1] ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						return;
					}
					else {
						if(ContainsString( os_info[3], "UBUNTU" )){
							version = eregmatch( pattern: "UBUNTU([0-9.]+)", string: os_info[3] );
							if( !isnull( version[1] ) ){
								version = ereg_replace( pattern: "^([0-9]{1,2})(04|10)$", string: version[1], replace: "\\1.\\2" );
								os_register_and_report( os: "Ubuntu", version: version, cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							return;
						}
					}
				}
			}
			else {
				return;
			}
		}
		if(ContainsString( banner, "Server: CUPS/" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			if(!egrep( pattern: "^Server: CUPS/[0-9.]+ IPP/[0-9.]+$", string: banner ) && !egrep( pattern: "^Server: CUPS/[0-9.]+$", string: banner )){
				os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "http_banner", port: port );
			}
			return;
		}
		if(ContainsString( banner, "Server: PowerDNS" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			if(egrep( pattern: "^Server: PowerDNS/([0-9.]+)$", string: banner )){
				return;
			}
		}
		if(ContainsString( banner, "Server: tinyproxy" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			if(egrep( pattern: "^Server: tinyproxy/([0-9.]+)$", string: banner )){
				return;
			}
		}
		if(egrep( pattern: "^Server: .*Linux", string: banner, icase: TRUE )){
			version = eregmatch( pattern: "Server: .*Linux(/|\\-)([0-9.x]+)", string: banner, icase: TRUE );
			if( !isnull( version[2] ) ){
				os_register_and_report( os: "Linux", version: version[2], cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			return;
		}
		if(IsMatchRegexp( banner, "Server: (NetWare HTTP Stack|Apache.+\\(NETWARE\\))" )){
			os_register_and_report( os: "Novell NetWare / Open Enterprise Server (OES)", cpe: "cpe:/o:novell:open_enterprise_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: (NetApp|Data ONTAP)", string: banner, icase: FALSE )){
			os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: ioLogik Web Server", string: banner, icase: FALSE )){
			os_register_and_report( os: "Moxa ioLogik Firmware", cpe: "cpe:/o:moxa:iologik_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Server: TreeNeWS" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: eWON", string: banner, icase: FALSE )){
			os_register_and_report( os: "eWON Firmware", cpe: "cpe:/o:ewon:ewon_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: xxxxxxxx-xxxxx", string: banner, icase: FALSE )){
			os_register_and_report( os: "FortiOS", cpe: "cpe:/o:fortinet:fortios", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: KM-MFP-http", string: banner, icase: FALSE )){
			os_register_and_report( os: "Kyocera MFP Firmware", cpe: "cpe:/o:kyocera:mfp_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: ClearSCADA", string: banner, icase: FALSE )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(egrep( pattern: "^Server: LANCOM", string: banner, icase: FALSE )){
			os_register_and_report( os: "LANCOM Firmware", cpe: "cpe:/o:lancom:lancom_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server: (HUAWEI|HuaWei|AR|WLAN)", string: banner, icase: FALSE )){
			os_register_and_report( os: "Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe: "cpe:/o:huawei:vrp_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Server: Grandstream GXP" )){
			os_register_and_report( os: "Grandstream GXP Firmware", cpe: "cpe:/o:grandstream:gxp_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*DrayTek/Vigor", string: banner, icase: FALSE )){
			os_register_and_report( os: "DrayTek Vigor Firmware", cpe: "cpe:/o:draytek:vigor_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*cwpsrv", string: banner, icase: FALSE )){
			os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*xxxx$", string: banner, icase: FALSE )){
			os_register_and_report( os: "Sophos SFOS", cpe: "cpe:/o:sophos:sfos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*lighttpd/.+SATO", string: banner, icase: FALSE )){
			os_register_and_report( os: "SATO Printer Firmware", cpe: "cpe:/o:sato:printer_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*(SEPM|Symantec Endpoint Protection Manager)", string: banner, icase: TRUE )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*Contiki/", string: banner, icase: TRUE )){
			os_register_and_report( os: "Contiki OS", cpe: "cpe:/o:contiki-os:contiki", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*Ethernut", string: banner, icase: TRUE )){
			os_register_and_report( os: "Ethernut (Nut/OS)", cpe: "cpe:/o:ethernut:nut_os", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*Loxone", string: banner, icase: TRUE )){
			os_register_and_report( os: "Loxone Miniserver Firmware", cpe: "cpe:/o:loxone:miniserver_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( pattern: "^Server\\s*:\\s*CirCarLife Scada", string: banner, icase: TRUE )){
			os_register_and_report( os: "Circontrol CirCarLife Firmware", cpe: "cpe:/o:circontrol:circarlife_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*NexusDB WebServer", icase: TRUE )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*TP-LINK HTTPD", icase: TRUE )){
			os_register_and_report( os: "TP-Link Unknown Device Firmware", cpe: "cpe:/o:tp-link:unknown_device_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*FSL DLNADOC", icase: TRUE )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*PsiOcppApp", icase: TRUE )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*Raption", icase: TRUE )){
			os_register_and_report( os: "Circontrol Raption Firmware", cpe: "cpe:/o:circontrol:raption_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*SonicWALL", icase: TRUE )){
			os_register_and_report( os: "SonicWall SMA / SRA Firmware", cpe: "cpe:/o:sonicwall:unknown_device_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*HP HTTP Server; HP", icase: TRUE )){
			os_register_and_report( os: "HP Printer Firmware", cpe: "cpe:/o:hp:printer_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*HP HTTP Server; Samsung", icase: TRUE )){
			os_register_and_report( os: "Samsung Printer Firmware", cpe: "cpe:/o:samsung:printer_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^[Ss]erver\\s*:\\s*MSA(/[0-9.]+)?$", icase: FALSE )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(egrep( string: banner, pattern: "^Server\\s*:\\s*Start HTTP\\-Server", icase: TRUE )){
			os_register_and_report( os: "Ruije Networks Device Firmware", cpe: "cpe:/o:ruijie_networks:device_firmware", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "http_banner", port: port );
	}
	return;
}
func check_php_banner( port, host ){
	var port, host;
	var checkFiles, dir, phpFilesList, count, phpFile, checkFile, banner, phpBanner, phpscriptsUrls, phpscriptsUrl, _phpBanner, banner_type;
	checkFiles = make_list();
	for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
		if(dir == "/"){
			dir = "";
		}
		checkFiles = make_list( checkFiles,
			 dir + "/",
			 dir + "/index.php" );
	}
	phpFilesList = http_get_kb_file_extensions( port: port, host: host, ext: "php" );
	if(phpFilesList && is_array( phpFilesList )){
		count = 0;
		for phpFile in phpFilesList {
			count++;
			checkFiles = nasl_make_list_unique( checkFiles, phpFile );
			if(count >= 10){
				break;
			}
		}
	}
	for checkFile in checkFiles {
		banner = http_get_remote_headers( port: port, file: checkFile );
		phpBanner = egrep( pattern: "^X-Powered-By\\s*:\\s*PHP/.+$", string: banner, icase: TRUE );
		if(!phpBanner){
			continue;
		}
		phpBanner = chomp( phpBanner );
		if(egrep( pattern: "^X-Powered-By\\s*:\\s*PHP/[0-9.]+(-[0-9.]+)?$", string: phpBanner )){
			phpBanner = NULL;
			continue;
		}
		banner_type = "PHP Server banner";
		break;
	}
	if(!phpBanner){
		phpscriptsUrls = get_kb_list( "php/banner/from_scripts/" + host + "/" + port + "/urls" );
		if(phpscriptsUrls && is_array( phpscriptsUrls )){
			for phpscriptsUrl in phpscriptsUrls {
				_phpBanner = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + phpscriptsUrl );
				if(_phpBanner && IsMatchRegexp( _phpBanner, "[0-9.]+" )){
					banner_type = "phpinfo()/ACP(u) output";
					phpBanner = _phpBanner;
					break;
				}
			}
		}
	}
	if(phpBanner){
		if(ContainsString( phpBanner, "sury.org" )){
			version = eregmatch( pattern: "\\+ubuntu([0-9.]+)", string: phpBanner );
			if(!isnull( version[1] )){
				os_register_and_report( os: "Ubuntu", version: version[1], cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
		}
		if( ContainsString( phpBanner, "~warty" ) ){
			os_register_and_report( os: "Ubuntu", version: "4.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		else {
			if( ContainsString( phpBanner, "~hoary" ) ){
				os_register_and_report( os: "Ubuntu", version: "5.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			else {
				if( ContainsString( phpBanner, "~breezy" ) ){
					os_register_and_report( os: "Ubuntu", version: "5.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					return;
				}
				else {
					if( ContainsString( phpBanner, "~dapper" ) ){
						os_register_and_report( os: "Ubuntu", version: "6.06", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						return;
					}
					else {
						if( ContainsString( phpBanner, "~edgy" ) ){
							os_register_and_report( os: "Ubuntu", version: "6.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							return;
						}
						else {
							if( ContainsString( phpBanner, "~feisty" ) ){
								os_register_and_report( os: "Ubuntu", version: "7.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								return;
							}
							else {
								if( ContainsString( phpBanner, "~gutsy" ) ){
									os_register_and_report( os: "Ubuntu", version: "7.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									return;
								}
								else {
									if( ContainsString( phpBanner, "~hardy" ) ){
										os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										return;
									}
									else {
										if( ContainsString( phpBanner, "~intrepid" ) ){
											os_register_and_report( os: "Ubuntu", version: "8.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											return;
										}
										else {
											if( ContainsString( phpBanner, "~jaunty" ) ){
												os_register_and_report( os: "Ubuntu", version: "9.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												return;
											}
											else {
												if( ContainsString( phpBanner, "~karmic" ) ){
													os_register_and_report( os: "Ubuntu", version: "9.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													return;
												}
												else {
													if( ContainsString( phpBanner, "~lucid" ) ){
														os_register_and_report( os: "Ubuntu", version: "10.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														return;
													}
													else {
														if( ContainsString( phpBanner, "~maverick" ) ){
															os_register_and_report( os: "Ubuntu", version: "10.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															return;
														}
														else {
															if( ContainsString( phpBanner, "~natty" ) ){
																os_register_and_report( os: "Ubuntu", version: "11.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																return;
															}
															else {
																if( ContainsString( phpBanner, "~oneiric" ) ){
																	os_register_and_report( os: "Ubuntu", version: "11.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	return;
																}
																else {
																	if( ContainsString( phpBanner, "~precise" ) ){
																		os_register_and_report( os: "Ubuntu", version: "12.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		return;
																	}
																	else {
																		if( ContainsString( phpBanner, "~quantal" ) ){
																			os_register_and_report( os: "Ubuntu", version: "12.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			return;
																		}
																		else {
																			if( ContainsString( phpBanner, "~raring" ) ){
																				os_register_and_report( os: "Ubuntu", version: "13.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																				return;
																			}
																			else {
																				if( ContainsString( phpBanner, "~saucy" ) ){
																					os_register_and_report( os: "Ubuntu", version: "13.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																					return;
																				}
																				else {
																					if( ContainsString( phpBanner, "~trusty" ) ){
																						os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																						return;
																					}
																					else {
																						if( ContainsString( phpBanner, "~utopic" ) ){
																							os_register_and_report( os: "Ubuntu", version: "14.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																							return;
																						}
																						else {
																							if( ContainsString( phpBanner, "~vivid" ) ){
																								os_register_and_report( os: "Ubuntu", version: "15.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																								return;
																							}
																							else {
																								if( ContainsString( phpBanner, "~wily" ) ){
																									os_register_and_report( os: "Ubuntu", version: "15.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																									return;
																								}
																								else {
																									if( ContainsString( phpBanner, "~xenial" ) ){
																										os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																										return;
																									}
																									else {
																										if( ContainsString( phpBanner, "~yakkety" ) ){
																											os_register_and_report( os: "Ubuntu", version: "16.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																											return;
																										}
																										else {
																											if( ContainsString( phpBanner, "~zesty" ) ){
																												os_register_and_report( os: "Ubuntu", version: "17.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																												return;
																											}
																											else {
																												if( ContainsString( phpBanner, "~artful" ) ){
																													os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																													return;
																												}
																												else {
																													if( ContainsString( phpBanner, "~bionic" ) ){
																														os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																														return;
																													}
																													else {
																														if( ContainsString( phpBanner, "~cosmic" ) ){
																															os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																															return;
																														}
																														else {
																															if( ContainsString( phpBanner, "~disco" ) ){
																																os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																return;
																															}
																															else {
																																if( ContainsString( phpBanner, "~eoan" ) ){
																																	os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																	return;
																																}
																																else {
																																	if(ContainsString( phpBanner, "~focal" )){
																																		os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																																		return;
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
		if(ContainsString( phpBanner, "ubuntu" )){
			if( ContainsString( phpBanner, "ubuntu0.20.04" ) ){
				os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( phpBanner, "ubuntu0.19.10" ) ){
					os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( phpBanner, "ubuntu0.19.04" ) ){
						os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( phpBanner, "PHP/7.2.10-0ubuntu1" ) ){
							os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( phpBanner, "PHP/7.2.3-1ubuntu1" ) ){
								os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( phpBanner, "PHP/5.2.4-2ubuntu5.10" ) ){
									os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
							}
						}
					}
				}
			}
			return;
		}
		if( IsMatchRegexp( phpBanner, "[+\\-~.]bookworm" ) ){
			os_register_and_report( os: "Debian GNU/Linux", version: "12", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		else {
			if( IsMatchRegexp( phpBanner, "[+\\-~.]bullseye" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "11", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			else {
				if( IsMatchRegexp( phpBanner, "[+\\-~.]buster" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					return;
				}
				else {
					if( IsMatchRegexp( phpBanner, "[+\\-~.]stretch" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						return;
					}
					else {
						if( IsMatchRegexp( phpBanner, "[+\\-~.]jessie" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							return;
						}
						else {
							if( IsMatchRegexp( phpBanner, "[+\\-~.]wheezy" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								return;
							}
							else {
								if( IsMatchRegexp( phpBanner, "[+\\-~.]squeeze" ) ){
									os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									return;
								}
								else {
									if( IsMatchRegexp( phpBanner, "[+\\-~.]lenny" ) ){
										os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										return;
									}
									else {
										if( IsMatchRegexp( phpBanner, "[+\\-~.]etch" ) ){
											os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											return;
										}
										else {
											if( IsMatchRegexp( phpBanner, "[+\\-~.]sarge" ) ){
												os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												return;
											}
											else {
												if( IsMatchRegexp( phpBanner, "[+\\-~.]woody" ) ){
													os_register_and_report( os: "Debian GNU/Linux", version: "3.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													return;
												}
												else {
													if( IsMatchRegexp( phpBanner, "[+\\-~.]potato" ) ){
														os_register_and_report( os: "Debian GNU/Linux", version: "2.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
														return;
													}
													else {
														if( IsMatchRegexp( phpBanner, "[+\\-~.]slink" ) ){
															os_register_and_report( os: "Debian GNU/Linux", version: "2.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															return;
														}
														else {
															if( IsMatchRegexp( phpBanner, "[+\\-~.]hamm" ) ){
																os_register_and_report( os: "Debian GNU/Linux", version: "2.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																return;
															}
															else {
																if( IsMatchRegexp( phpBanner, "[+\\-~.]bo[0-9 ]+" ) ){
																	os_register_and_report( os: "Debian GNU/Linux", version: "1.3", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	return;
																}
																else {
																	if( IsMatchRegexp( phpBanner, "[+\\-~.]rex[0-9 ]+" ) ){
																		os_register_and_report( os: "Debian GNU/Linux", version: "1.2", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																		return;
																	}
																	else {
																		if(IsMatchRegexp( phpBanner, "[+\\-~.]buzz" )){
																			os_register_and_report( os: "Debian GNU/Linux", version: "1.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																			return;
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
		if(IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)" )){
			if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(4|etch)" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "4.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(5|lenny)" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(6|squeeze)" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(7|wheezy)" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(8|jessie)" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(9|stretch)" ) ){
									os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(10|buster)" ) ){
										os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(11|bullseye)" ) ){
											os_register_and_report( os: "Debian GNU/Linux", version: "11", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( IsMatchRegexp( phpBanner, "[+\\-~.](deb|dotdeb|bpo|debian)[+\\-~.]?(12|bookworm)" ) ){
												os_register_and_report( os: "Debian GNU/Linux", version: "12", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: phpBanner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return;
		}
		os_register_unknown_banner( banner: phpBanner, banner_type_name: banner_type, banner_type_short: "php_banner", port: port );
	}
	return;
}
func check_default_page( port ){
	var port, buf, banner_type, check;
	buf = http_get_cache( item: "/", port: port );
	if(buf && ( IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || IsMatchRegexp( buf, "^HTTP/1\\.[01] 403" ) )){
		banner_type = "HTTP Server default page";
		if(ContainsString( buf, "<title>Test Page for the Apache HTTP Server" ) || ContainsString( buf, "<title>Apache HTTP Server Test Page" ) || ContainsString( buf, "<title>Test Page for the Nginx HTTP Server" )){
			check = "on Red Hat Enterprise Linux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "powered by CentOS</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on CentOS</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Fedora Core</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Fedora Core", cpe: "cpe:/o:fedoraproject:fedora_core", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Fedora</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Fedora", cpe: "cpe:/o:fedoraproject:fedora", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "powered by Ubuntu</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "powered by Debian</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Mageia</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Mageia", cpe: "cpe:/o:mageia:linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on EPEL</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Scientific Linux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Scientific Linux", cpe: "cpe:/o:scientificlinux:scientificlinux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on the Amazon Linux AMI</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Amazon Linux", cpe: "cpe:/o:amazon:linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on CloudLinux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "CloudLinux", cpe: "cpe:/o:cloudlinux:cloudlinux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on SLES Expanded Support Platform</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "SUSE Linux Enterprise Server", cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on EulerOS Linux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Huawei EulerOS", cpe: "cpe:/o:huawei:euleros", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on openEuler Linux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Huawei openEuler", cpe: "cpe:/o:huawei:openeuler", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Oracle Linux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Oracle Linux", cpe: "cpe:/o:oracle:linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "powered by Linux</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(check = eregmatch( string: buf, pattern: "<title>(Test Page for the (Apache|Nginx) HTTP Server|Apache HTTP Server Test Page) (powered by|on).*</title>" )){
				os_register_unknown_banner( banner: check[0], banner_type_name: banner_type, banner_type_short: "http_test_banner", port: port );
			}
			return;
		}
		if(ContainsString( buf, "<TITLE>Welcome to Jetty" )){
			check = "on Debian</TITLE>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(check = eregmatch( string: buf, pattern: "<TITLE>Welcome to Jetty.*on.*</TITLE>" )){
				os_register_unknown_banner( banner: check[0], banner_type_name: banner_type, banner_type_short: "http_test_banner", port: port );
			}
			return;
		}
		if(ContainsString( buf, "<title>Welcome to nginx" )){
			check = "on Debian!</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Ubuntu!</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Fedora!</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Fedora", cpe: "cpe:/o:fedoraproject:fedora", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "on Slackware!</title>";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Slackware", cpe: "cpe:/o:slackware:slackware_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(check = eregmatch( string: buf, pattern: "<title>Welcome to nginx on.*!</title>" )){
				os_register_unknown_banner( banner: check[0], banner_type_name: banner_type, banner_type_short: "http_test_banner", port: port );
			}
			return;
		}
		if(ContainsString( buf, "<title>Apache2" ) && ContainsString( buf, "Default Page: It works</title>" )){
			check = "<title>Apache2 Debian Default Page";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "<title>Apache2 Ubuntu Default Page";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			check = "<title>Apache2 centos Default Page";
			if(ContainsString( buf, check )){
				os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: check, desc: SCRIPT_DESC, runs_key: "unixoide" );
				return;
			}
			if(check = eregmatch( string: buf, pattern: "<title>Apache2 .* Default Page: It works</title>" )){
				os_register_unknown_banner( banner: check[0], banner_type_name: banner_type, banner_type_short: "http_test_banner", port: port );
			}
			return;
		}
		if(check = eregmatch( string: buf, pattern: "<TITLE>(Forbidden|Home|Not Found|Bad Request) - CUPS.*</TITLE>", icase: TRUE )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: check[0], desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
	}
	url = "/index.nginx-debian.html";
	buf = http_get_cache( item: url, port: port );
	if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<title>Welcome to nginx!</title>" )){
		os_register_and_report( os: "Debian GNU/Linux or Ubuntu", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: http_report_vuln_url( port: port, url: url, url_only: TRUE ), desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	return;
}
func check_x_powered_by_banner( port, banner ){
	var port, banner, banner_type;
	if(banner && banner = egrep( pattern: "^X-Powered-By\\s*:.*$", string: banner, icase: TRUE )){
		banner = chomp( banner );
		if(IsMatchRegexp( banner, "^X-Powered-By\\s*:\\s*$" )){
			return;
		}
		if(ContainsString( banner, " PHP" ) || egrep( pattern: "^X-Powered-By\\s*:\\s*PHP/[0-9.]+(-[0-9]+)?$", string: banner, icase: TRUE )){
			return;
		}
		if(banner == "X-Powered-By: Express"){
			return;
		}
		if(egrep( pattern: "^X-Powered-By\\s*:\\s*Servlet/([0-9.]+)$", string: banner, icase: TRUE )){
			return;
		}
		banner_type = "X-Powered-By Server banner";
		if(ContainsString( banner, "PleskWin" ) || ContainsString( banner, "ASP.NET" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		if(ContainsString( banner, "PleskLin" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(ContainsString( banner, "Phusion Passenger" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "http_x_powered_by_banner", port: port );
	}
	return;
}
func check_user_agent_banner( port, banner ){
	var port, banner, banner_type;
	if(banner && banner = egrep( pattern: "^User-Agent\\s*:.*$", string: banner, icase: TRUE )){
		banner = chomp( banner );
		if(IsMatchRegexp( banner, "^User-Agent\\s*:\\s*$" )){
			return;
		}
		if(ContainsString( banner, http_get_user_agent() )){
			return;
		}
		banner_type = "HTTP User Agent banner";
		if(IsMatchRegexp( banner, "User-Agent\\s*:\\s*LOOLWSD (WOPI|HTTP) Agent" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "http_user_agent_banner", port: port );
	}
	return;
}
func check_daap_banner( port, banner ){
	var port, banner, banner_type;
	if(banner && banner = egrep( pattern: "^DAAP-Server\\s*:.*$", string: banner, icase: TRUE )){
		banner = chomp( banner );
		if(IsMatchRegexp( banner, "^DAAP-Server\\s*:\\s*$" )){
			return;
		}
		if(IsMatchRegexp( banner, "^DAAP-Server\\s*:\\s*(Ampache|daap-sharp)$" )){
			return;
		}
		banner_type = "DAAP-Server banner";
		if(IsMatchRegexp( banner, "\\(OS X\\)" )){
			os_register_and_report( os: "Mac OS X / macOS", cpe: "cpe:/o:apple:mac_os_x", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			return;
		}
		if(IsMatchRegexp( banner, "\\(Windows\\)" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			return;
		}
		os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "daap_server_banner", port: port );
	}
	return;
}
port = http_get_port( default: 80, ignore_broken: TRUE );
banner = http_get_remote_headers( port: port, ignore_broken: TRUE );
if(!banner || !IsMatchRegexp( banner, "^HTTP/1\\.[01] " )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
check_php_banner( port: port, host: host );
check_http_banner( port: port, banner: banner );
check_default_page( port: port );
check_x_powered_by_banner( port: port, banner: banner );
check_user_agent_banner( port: port, banner: banner );
check_daap_banner( port: port, banner: banner );
if(concl = egrep( string: banner, pattern: "^X-OWA-Version\\s*:.+", icase: TRUE )){
	concl = chomp( concl );
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: "X-OWA-Version banner", port: port, banner: concl, desc: SCRIPT_DESC, runs_key: "windows" );
}
exit( 0 );

