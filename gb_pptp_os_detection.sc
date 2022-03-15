if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108682" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-10-22 08:02:28 +0000 (Tue, 22 Oct 2019)" );
	script_name( "Operating System (OS) Detection (PPTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "pptp_detect.sc" );
	script_mandatory_keys( "pptp/vendor_string/detected" );
	script_tag( name: "summary", value: "PPTP service based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (PPTP)";
BANNER_TYPE = "PPTP Service banner";
port = service_get_port( default: 1723, proto: "pptp" );
if(!vendor = get_kb_item( "pptp/" + port + "/vendor_string" )){
	exit( 0 );
}
hostname = get_kb_item( "pptp/" + port + "/hostname" );
if( tolower( vendor ) == "linux" ){
	os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
}
else {
	if( ContainsString( vendor, "MikroTik" ) ){
		os_register_and_report( os: "Mikrotik Router OS", cpe: "cpe:/o:mikrotik:routeros", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		if( ContainsString( vendor, "FreeBSD" ) ){
			os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( vendor, "DrayTek" ) || hostname == "Vigor" ){
				os_register_and_report( os: "DrayTek Vigor Firmware", cpe: "cpe:/o:draytek:vigor_firmware", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( vendor, "Microsoft" ) ){
					os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "windows" );
				}
				else {
					if( ContainsString( vendor, "Fortinet" ) ){
						os_register_and_report( os: "FortiOS", cpe: "cpe:/o:fortinet:fortios", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( vendor, "BUFFALO" ) ){
							os_register_and_report( os: "Buffalo Unknown Router Firmware", cpe: "cpe:/o:buffalotech:unknown_router_firmware", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( vendor, "TP-LINK" ) ){
								os_register_and_report( os: "TP-LINK Unknown Router Firmware", cpe: "cpe:/o:tp-link:unknown_router_firmware", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								if( ContainsString( vendor, "Cisco" ) ){
									os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									if( ContainsString( vendor, "Mac OS X" ) || ContainsString( vendor, "Apple Computer" ) ){
										os_register_and_report( os: "Mac OS X / macOS", cpe: "cpe:/o:apple:mac_os_x", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										if( ContainsString( vendor, "ZyXEL" ) ){
											os_register_and_report( os: "ZyXEL Unknown Router Firmware", cpe: "cpe:/o:zyxel:unknown_router_firmware", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											if( ContainsString( vendor, "D-Link" ) ){
												os_register_and_report( os: "D-Link Unknown Router Firmware", cpe: "cpe:/o:d-link:unknown_router_firmware", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												if( ContainsString( vendor, "Aruba" ) ){
													os_register_and_report( os: "Aruba Networks ArubaOS", cpe: "cpe:/o:arubanetworks:arubaos", banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
												}
												else {
													os_register_and_report( os: vendor, banner_type: BANNER_TYPE, banner: vendor, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
													if(vendor != "xxxxxx" && vendor != "Router" && vendor != "PPTP"){
														unknown_report = "\n - Vendor String: " + vendor;
														if(hostname){
															unknown_report += "\n - Hostname:      " + hostname;
														}
														os_register_unknown_banner( banner: unknown_report, banner_type_name: BANNER_TYPE, banner_type_short: "pptp_banner", port: port );
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

