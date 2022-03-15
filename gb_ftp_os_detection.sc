if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105355" );
	script_version( "2021-08-02T09:56:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-02 09:56:01 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-09-15 15:57:03 +0200 (Tue, 15 Sep 2015)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (FTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/banner/available" );
	script_tag( name: "summary", value: "FTP banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (FTP)";
BANNER_TYPE = "FTP banner";
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
banner = chomp( banner );
if(!banner || banner == "" || isnull( banner )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "CP ([0-9\\-]+) (IT )?FTP-Server V([0-9.]+) ready for new user" )){
	exit( 0 );
}
if(banner == "220 FTP server ready" || banner == "220 FTP server ready."){
	exit( 0 );
}
if(ContainsString( banner, " FTP server (MikroTik " )){
	exit( 0 );
}
if(banner == "220 Welcome message" || banner == "220 Service ready for new user."){
	exit( 0 );
}
if(ContainsString( banner, "500 OOPS: could not bind listening IPv4 socket" )){
	exit( 0 );
}
if(ContainsString( banner, "FTP server (Data ONTAP" )){
	os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "[vV]xWorks" ) && ContainsString( banner, "FTP server" )){
	version = eregmatch( pattern: "\\(?VxWorks ?\\(?([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Wind River VxWorks", version: version[1], cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "Network Management Card AOS" )){
	version = eregmatch( pattern: "Network Management Card AOS v([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "APC AOS", version: version[1], cpe: "cpe:/o:apc:aos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "APC AOS", cpe: "cpe:/o:apc:aos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(( ContainsString( banner, "Microsoft FTP Service" ) && ContainsString( banner, "WINDOWS SERVER 2003" ) ) || ContainsString( banner, "OS=Windows Server 2003;" )){
	os_register_and_report( os: "Microsoft Windows Server 2003", cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "MinWin FTP server" )){
	os_register_and_report( os: "Microsoft Windows 10 IoT", cpe: "cpe:/o:microsoft:windows_10:-:-:iot", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "OS=Windows 10;" )){
	os_register_and_report( os: "Microsoft Windows 10", cpe: "cpe:/o:microsoft:windows_10", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "OS=Windows 8;" )){
	os_register_and_report( os: "Microsoft Windows 8", cpe: "cpe:/o:microsoft:windows_8", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "OS=Windows 7;" )){
	os_register_and_report( os: "Microsoft Windows 7", cpe: "cpe:/o:microsoft:windows_7", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "OS=Windows XP;" )){
	os_register_and_report( os: "Microsoft Windows XP", cpe: "cpe:/o:microsoft:windows_xp", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "ProFTPD" ) && ContainsString( banner, "(Windows" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "FileZilla Server" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "FTP Server for Windows" ) || ContainsString( banner, "220 FTP to Windows" ) || ContainsString( banner, "FTP/S Server for Windows" ) || ContainsString( banner, "Microsoft FTP Service" ) || ContainsString( banner, "220 Windows server" ) || ContainsString( banner, "220 -Microsoft FTP server" ) || ContainsString( banner, "running on Windows " ) || ContainsString( banner, "Windows FTP Server" ) || ContainsString( banner, "Windows NT XDS FTP server" ) || ContainsString( banner, "220 Welcom to Windows" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "Windows Server 2008 SP2" )){
	os_register_and_report( os: "Microsoft Windows Server 2008 SP2", cpe: "cpe:/o:microsoft:windows_server_2008:-:sp2", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "running on Windows Server 2008 R2 Enterprise" ) || ContainsString( banner, "OS=Windows Server 2008 R2;" )){
	os_register_and_report( os: "Microsoft Windows Server 2008 R2", cpe: "cpe:/o:microsoft:windows_server_2008:r2", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "running on Windows 2008" )){
	os_register_and_report( os: "Microsoft Windows Server 2008", cpe: "cpe:/o:microsoft:windows_server_2008", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "Windows Server 2012 R2" )){
	os_register_and_report( os: "Microsoft Windows Server 2012 R2", cpe: "cpe:/o:microsoft:windows_server_2012:r2", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "OS=Windows Server 2012;" )){
	os_register_and_report( os: "Microsoft Windows Server 2012", cpe: "cpe:/o:microsoft:windows_server_2012", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "220-Debian GNU/Linux" )){
	version = eregmatch( pattern: "Debian GNU/Linux ([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "ProFTPD" )){
	if(ContainsString( banner, "(Debian)" ) || ContainsString( banner, "(Raspbian)" )){
		os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "(Gentoo)" )){
		os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "(powered by SuSE Linux)" )){
		os_register_and_report( os: "SUSE Linux", cpe: "cpe:/o:novell:suse_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "220-CentOS release" )){
		os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "(ubuntu)" )){
		os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
}
if(ContainsString( banner, "This is a Linux PC" ) || ContainsString( banner, "Linux FTP Server" )){
	os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "220-Red Hat Enterprise Linux Server" )){
	os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "220[- ]Welcome to SUSE Linux Enterprise Server" )){
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
if(ContainsString( banner, "220-Welcome to openSUSE" )){
	os_register_and_report( os: "openSUSE", cpe: "cpe:/o:novell:opensuse", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "FTP server (NetBSD-ftpd" )){
	os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "220-OpenBSD" ) || IsMatchRegexp( banner, "FTP server \\(Version ([0-9.]+)/OpenBSD/Linux-ftpd-([0-9.]+)\\) ready" )){
	os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "FTP server (SunOS" )){
	version = eregmatch( pattern: "FTP server \\(SunOS ([0-9.]+)", string: banner );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", version: version[1], banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( banner, "220 Solaris FTP Server" ) || ContainsString( banner, "(Sun Solaris" )){
	os_register_and_report( os: "Sun Solaris", cpe: "cpe:/o:sun:solaris", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "220 (vsFTPd" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Pure-FTPd" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "FTP server (Version wu-" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "ManageUPSnet FTP server" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Zimbra LMTP server ready" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "FTP server \\(Version ([0-9.]+)/ARMLinux/Linux-ftpd-([0-9.]+)\\) ready" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "FTP server (Linux-ftpd) ready." )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(eregmatch( pattern: "^220[- ]QTCP at .+", string: banner, icase: FALSE )){
	os_register_and_report( os: "IBM iSeries / OS/400", cpe: "cpe:/o:ibm:os_400", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "IOS-FTP server" ) && ContainsString( banner, "ready." )){
	os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "220 Titan FTP Server" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "220 DrayTek FTP" )){
	os_register_and_report( os: "DrayTek Vigor Firmware", cpe: "cpe:/o:draytek:vigor_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(banner == "220 FTP service ready."){
	os_register_and_report( os: "Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe: "cpe:/o:huawei:vrp_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "220 KONICA MINOLTA FTP server ready." )){
	os_register_and_report( os: "KONICA MINOLTA Printer Firmware", cpe: "cpe:/o:konicaminolta:printer_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "220[- ](AXIS|Axis).*Network Camera" )){
	os_register_and_report( os: "Axis Network Camera Firmware", cpe: "cpe:/o:axis:network_camera_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "xlweb FTP server" )){
	os_register_and_report( os: "Honeywell Excel Web Controller Firmware", cpe: "cpe:/o:honeywell:xl_web_ii_controller", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "Welcome to Linksys" )){
	os_register_and_report( os: "Linksys Device Firmware", cpe: "cpe:/o:linksys:device_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(egrep( string: banner, pattern: "\\((ZyWALL )?USG (FLEX )?[0-9]{2,}", icase: FALSE )){
	os_register_and_report( os: "Zyxel USG Firmware", cpe: "cpe:/o:zyxel:usg_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, " FTP server " ) && ContainsString( banner, "(OEM FTPD version" )){
	os_register_and_report( os: "Epson Printer Firmware", cpe: "cpe:/o:epson:printer_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
syst_banner = get_kb_item( "ftp/fingerprints/" + port + "/syst_banner_noauth" );
if(ContainsString( syst_banner, "215 UNIX " ) && ContainsString( syst_banner, "Version: BSD" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "ftp_banner", port: port );
exit( 0 );

