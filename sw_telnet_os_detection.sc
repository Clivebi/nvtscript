if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111069" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-12-13 13:00:00 +0100 (Sun, 13 Dec 2015)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "summary", value: "Telnet banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("dump.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (Telnet)";
BANNER_TYPE = "Telnet banner";
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || banner == "" || isnull( banner )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "^\\s*User(name)?\\s*:\\s*$" )){
	exit( 0 );
}
if(ContainsString( banner, "Welcome to Microsoft Telnet Service" ) || ContainsString( banner, "Georgia SoftWorks Telnet Server for Windows" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "Welcome to the Windows CE Telnet Service" ) || ContainsString( banner, "Windows CE Telnet Service cannot accept anymore concurrent users" )){
	os_register_and_report( os: "Microsoft Windows CE", cpe: "cpe:/o:microsoft:windows_ce", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "FreeBSD/" ) && ( ContainsString( banner, "(tty" ) || ContainsString( banner, "(pts" ) )){
	os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "NetBSD/" ) && ( ContainsString( banner, "(tty" ) || ContainsString( banner, "(pts" ) )){
	os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "ManageUPSnet" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "CMC-TC-PU2" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "User Access Verification" ) && ContainsString( banner, "Username:" )){
	os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "Copyright \\(c\\) [0-9]+ - [0-9]+ ((Juniper|Trapeze) Networks, Inc|3Com Corporation)\\. All rights reserved\\." )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "metasploitable login:" ) && ContainsString( banner, "Warning: Never expose this VM to an untrusted network!" )){
	os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "SunOS" ) && ContainsString( banner, "login:" )){
	version = eregmatch( pattern: "SunOS ([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "SunOS", version: version[1], cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "VxWorks login:" ) || ContainsString( banner, "Welcome to NetLinx" )){
	os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Draytek login:" )){
	os_register_and_report( os: "DrayTek Vigor Firmware", cpe: "cpe:/o:draytek:vigor_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Debian GNU/Linux" )){
	version = eregmatch( pattern: "Debian GNU/Linux ([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
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
				if( ContainsString( banner, "wheezy" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "jessie" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
				}
			}
		}
	}
	exit( 0 );
}
if(ContainsString( banner, "Ubuntu" )){
	os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "CentOS release" )){
	os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Fedora release" )){
	os_register_and_report( os: "Fedora", cpe: "cpe:/o:fedoraproject:fedora", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Fedora Core release" )){
	os_register_and_report( os: "Fedora Core", cpe: "cpe:/o:fedoraproject:fedora_core", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Red Hat Enterprise Linux" )){
	version = eregmatch( pattern: "Red Hat Enterprise Linux (Server|ES|AS|Client) release ([0-9.]+)", string: banner );
	if( !isnull( version[2] ) ){
		os_register_and_report( os: "Red Hat Enterprise Linux " + version[1], version: version[2], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "Red Hat Linux release" )){
	os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "-gentoo-" )){
	os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "Welcome to SUSE Linux Enterprise Server" )){
	version = eregmatch( pattern: "Welcome to SUSE Linux Enterprise Server( for SAP Applications)? ([0-9.]+) (SP[0-9]+)?", string: banner, icase: TRUE );
	if( !isnull( version[2] ) ){
		if( !isnull( version[3] ) ) {
			os_register_and_report( os: "SUSE Linux Enterprise Server", version: version[2], patch: version[3], cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			os_register_and_report( os: "SUSE Linux Enterprise Server", version: version[2], cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
	}
	else {
		os_register_and_report( os: "SUSE Linux Enterprise Server", cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( banner, "Welcome to SUSE Linux" )){
	version = eregmatch( pattern: "Welcome to SuSE Linux ([0-9.]+)", string: banner, icase: TRUE );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "SUSE Linux", version: version[1], cpe: "cpe:/o:novell:suse_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "SUSE Linux", cpe: "cpe:/o:novell:suse_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "Welcome to openSUSE Leap" )){
	version = eregmatch( pattern: "Welcome to openSUSE Leap ([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "openSUSE Leap", version: version[1], cpe: "cpe:/o:opensuse_project:leap", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "openSUSE Leap", cpe: "cpe:/o:opensuse_project:leap", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "Welcome to openSUSE" )){
	version = eregmatch( pattern: "Welcome to openSUSE ([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "openSUSE", version: version[1], cpe: "cpe:/o:novell:opensuse", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "openSUSE", cpe: "cpe:/o:novell:opensuse", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( banner, "^\r\n\r\nData ONTAP" )){
	os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Welcome to the DataStream " )){
	mod = eregmatch( pattern: "Welcome to the DataStream\\s*([^- ]+)", string: banner );
	if( !isnull( mod[1] ) ){
		cpe_model = str_replace( string: tolower( mod[1] ), find: " ", replace: "_" );
		os_register_and_report( os: "Synetica DataStream - " + mod[1] + " Firmware", cpe: "cpe:/o:synetica:datastream_" + cpe_model + "_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Synetica DataStream - Unknown Model Firmware", cpe: "cpe:/o:synetica:datastream_unknown_model_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "Grandstream GXP" )){
	os_register_and_report( os: "Grandstream GXP Firmware", cpe: "cpe:/o:grandstream:gxp_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Model: ZNID-GPON" )){
	os_register_and_report( os: "ZHONE ZNID GPON Firmware", cpe: "cpe:/o:dasanzhone:znid_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." ) || ( ContainsString( banner, "Login authentication" ) && ContainsString( banner, "Username:" ) )){
	os_register_and_report( os: "Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe: "cpe:/o:huawei:vrp_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Fabric OS" )){
	exit( 0 );
}
if(ContainsString( banner, "geneko login:" )){
	os_register_and_report( os: "Geneko Router Firmware", cpe: "cpe:/o:geneko:router_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Welcome to ZyWALL USG" )){
	os_register_and_report( os: "Zyxel USG Firmware", cpe: "cpe:/o:zyxel:usg_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "xlweb login:" )){
	os_register_and_report( os: "Honeywell Excel Web Controller Firmware", cpe: "cpe:/o:honeywell:xl_web_ii_controller", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(eregmatch( string: banner, pattern: "^\r\n(\\(none\\) |host )?login: $", icase: TRUE )){
	exit( 0 );
}
hosts = create_hostname_parts_list();
ip = get_host_ip();
hosts = make_list( hosts,
	 ip );
pattern = "^\r\n(";
for host in hosts {
	pattern += host + "|";
}
pattern = ereg_replace( string: pattern, pattern: "\\|$", replace: "" );
pattern += ") login: $";
pattern = str_replace( string: pattern, find: ".", replace: "\\." );
if(eregmatch( string: banner, pattern: pattern, icase: TRUE )){
	exit( 0 );
}
if(eregmatch( string: banner, pattern: "^\r\nAuthorized users only\\. All activities may be monitored and reported\\.\r\n[^ ]+ login: $", icase: FALSE )){
	exit( 0 );
}
if(banner == "\r\nToo many users logged in!  Please try again later.\r\n"){
	exit( 0 );
}
if(telnet_has_login_prompt( data: banner )){
	os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "telnet_banner", port: port );
}
exit( 0 );

