if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108201" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/detected" );
	script_tag( name: "summary", value: "SIP banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (SIP)";
BANNER_TYPE = "SIP server banner";
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
sip_get_banner( port: port, proto: proto );
if(!full_banner = get_kb_item( "sip/full_banner/" + proto + "/" + port )){
	exit( 0 );
}
serverbanner = get_kb_item( "sip/server_banner/" + proto + "/" + port );
if(serverbanner){
	concluded = "Server Banner: " + serverbanner;
}
uabanner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
if(uabanner){
	if(concluded){
		concluded += "\n";
	}
	concluded = "User-Agent Banner: " + uabanner;
}
if(serverbanner){
	if(ContainsString( serverbanner, "snom" )){
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( serverbanner, "+deb10" )){
		os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( serverbanner, "+deb9" )){
		os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( serverbanner, "+deb8" )){
		os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( serverbanner, "~dfsg" )){
		os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( serverbanner, "Microsoft-Windows" )){
		os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(ContainsString( tolower( serverbanner ), "kamailio" )){
		if(ContainsString( serverbanner, "/linux))" )){
			os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( serverbanner, "/solaris))" )){
			os_register_and_report( os: "Sun Solaris", cpe: "cpe:/o:sun:solaris", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( serverbanner, "/freebsd))" )){
			os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( serverbanner, "/openbsd))" )){
			os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
	}
	if(ContainsString( serverbanner, "Grandstream UCM" )){
		os_register_and_report( os: "Grandstream UCM Firmware", cpe: "cpe:/o:grandstream:ucm_firmware", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
}
if(uabanner){
	if(ContainsString( uabanner, "FRITZ!OS" ) || ContainsString( uabanner, "AVM FRITZ" )){
		os_register_and_report( os: "AVM FRITZ!OS", cpe: "cpe:/o:avm:fritz%21_os", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( uabanner, "OS/Windows" )){
		if( ContainsString( uabanner, "OS/Windows 7" ) ){
			os_register_and_report( os: "Microsoft Windows 7", cpe: "cpe:/o:microsoft:windows_7", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "windows" );
		}
		else {
			if( ContainsString( uabanner, "OS/Windows 8.1" ) ){
				os_register_and_report( os: "Microsoft Windows 8.1", cpe: "cpe:/o:microsoft:windows_8.1", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "windows" );
			}
			else {
				if( ContainsString( uabanner, "OS/Windows 8" ) ){
					os_register_and_report( os: "Microsoft Windows 8", cpe: "cpe:/o:microsoft:windows_8", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "windows" );
				}
				else {
					if( ContainsString( uabanner, "OS/Windows 10" ) ){
						os_register_and_report( os: "Microsoft Windows 10", cpe: "cpe:/o:microsoft:windows_10", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "windows" );
					}
					else {
						os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "windows" );
						os_register_unknown_banner( banner: uabanner, banner_type_name: BANNER_TYPE, banner_type_short: "sip_banner", port: port, proto: proto );
					}
				}
			}
		}
		exit( 0 );
	}
	if(ContainsString( uabanner, "Alcatel-Lucent" ) && ContainsString( uabanner, "ACS" )){
		os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( uabanner, "System[Linux" )){
		version = eregmatch( pattern: "System\\[Linux-([0-9.]+)", string: uabanner );
		if( !isnull( version[1] ) ){
			os_register_and_report( os: "Linux", version: version[1], cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		exit( 0 );
	}
	if(ContainsString( uabanner, "IceWarp SIP" )){
		if( os_info = eregmatch( pattern: "IceWarp SIP ([0-9.]+) ([^ ]+) ([^ ]+)( [^ ]+)?", string: uabanner, icase: FALSE ) ){
			if( max_index( os_info ) == 5 ){
				offset = 1;
			}
			else {
				offset = 0;
			}
			if( ContainsString( os_info[2 + offset], "RHEL" ) ){
				version = eregmatch( pattern: "RHEL([0-9.]+)", string: os_info[2 + offset] );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				exit( 0 );
			}
			else {
				if( ContainsString( os_info[2 + offset], "DEB" ) ){
					version = eregmatch( pattern: "DEB([0-9.]+)", string: os_info[2 + offset] );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					exit( 0 );
				}
				else {
					if(ContainsString( os_info[2 + offset], "UBUNTU" )){
						version = eregmatch( pattern: "UBUNTU([0-9.]+)", string: os_info[2 + offset] );
						if( !isnull( version[1] ) ){
							version = ereg_replace( pattern: "^([0-9]{1,2})(04|10)$", string: version[1], replace: "\\1.\\2" );
							os_register_and_report( os: "Ubuntu", version: version, cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						exit( 0 );
					}
				}
			}
		}
		else {
			exit( 0 );
		}
	}
	if(ContainsString( uabanner, "LANCOM " )){
		os_register_and_report( os: "LANCOM Firmware", cpe: "cpe:/o:lancom:lancom_firmware", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(IsMatchRegexp( uabanner, "Auerswald COMpact" )){
		os_register_and_report( os: "Auerswald COMpact Firmware", cpe: "cpe:/o:auerswald:compact_firmware", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(IsMatchRegexp( uabanner, "Grandstream GXP" )){
		os_register_and_report( os: "Grandstream GXP Firmware", cpe: "cpe:/o:grandstream:gxp_firmware", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(IsMatchRegexp( uabanner, "Cisco[- ]ATA ?[0-9]{3}" ) || IsMatchRegexp( serverbanner, "Cisco[- ]ATA ?[0-9]{3}" )){
		os_register_and_report( os: "Cisco ATA Analog Telephone Adapter Firmware", cpe: "cpe:/o:cisco:ata_analog_telephone_adaptor_firmware", banner_type: BANNER_TYPE, port: port, proto: proto, banner: concluded, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
}
os_register_unknown_banner( banner: full_banner, banner_type_name: BANNER_TYPE, banner_type_short: "sip_banner", port: port, proto: proto );
exit( 0 );

