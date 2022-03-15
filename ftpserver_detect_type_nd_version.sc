if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10092" );
	script_version( "2021-09-13T12:24:15+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:24:15 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "FTP Banner Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Product detection" );
	script_dependencies( "find_service2.sc", "find_service_3digits.sc", "ftpd_no_cmd.sc", "secpod_ftp_anonymous.sc" );
	script_require_ports( "Services/ftp", 21, 990 );
	script_tag( name: "summary", value: "This Plugin detects and reports a FTP Server Banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
ports = ftp_get_ports();
for port in ports {
	banner = ftp_get_banner( port: port );
	if(!banner){
		continue;
	}
	bannerlo = tolower( banner );
	guess = NULL;
	if(service_is_unknown( port: port )){
		service_register( port: port, proto: "ftp", message: "A FTP Server seems to be running on this port." );
	}
	help = ftp_get_cmd_banner( port: port, cmd: "HELP" );
	syst = ftp_get_cmd_banner( port: port, cmd: "SYST" );
	stat = ftp_get_cmd_banner( port: port, cmd: "STAT" );
	set_kb_item( name: "ftp/banner/available", value: TRUE );
	install = port + "/tcp";
	if(ContainsString( banner, "NcFTPd" )){
		set_kb_item( name: "ftp/ncftpd/detected", value: TRUE );
		register_product( cpe: "cpe:/a:ncftpd:ftp_server", location: install, port: port );
		guess += "\n- NcFTPd";
	}
	if(ContainsString( banner, "FtpXQ FTP" )){
		set_kb_item( name: "ftp/ftpxq/detected", value: TRUE );
		guess += "\n- FtpXQ FTP";
	}
	if(ContainsString( banner, "Cerberus FTP" )){
		set_kb_item( name: "ftp/cerberus/detected", value: TRUE );
		guess += "\n- Cerberus FTP";
	}
	if(ContainsString( banner, "Home Ftp Server" )){
		set_kb_item( name: "ftp/home_ftp/detected", value: TRUE );
		guess += "\n- Home FTP Server";
	}
	if(ContainsString( banner, "Welcome to DXM's FTP Server" )){
		set_kb_item( name: "ftp/xm_easy_personal/detected", value: TRUE );
		guess += "\n- XM Easy Personal FTP Server";
	}
	if(ContainsString( banner, "VicFTPS" )){
		set_kb_item( name: "ftp/vicftps/detected", value: TRUE );
		guess += "\n- VicFTPS";
	}
	if(ContainsString( banner, "Core FTP Server" )){
		set_kb_item( name: "ftp/core_ftp/detected", value: TRUE );
		guess += "\n- Core FTP";
	}
	if(ContainsString( banner, "Femitter FTP Server ready." )){
		set_kb_item( name: "ftp/femitter_ftp/detected", value: TRUE );
		guess += "\n- Femitter FTP Server";
	}
	if(ContainsString( banner, "FileCOPA FTP Server" )){
		set_kb_item( name: "ftp/intervations/filecopa/detected", value: TRUE );
		guess += "\n- InterVations FileCOPA FTP Server";
	}
	if(IsMatchRegexp( banner, "220[- ]+smallftpd" )){
		set_kb_item( name: "ftp/smallftpd/detected", value: TRUE );
		guess += "\n- Small FTPD Server";
	}
	if(ContainsString( banner, "TYPSoft FTP Server" )){
		set_kb_item( name: "ftp/typsoft/detected", value: TRUE );
		guess += "\n- TYPSoft FTP Server";
	}
	if(ContainsString( banner, "DSC ftpd" )){
		set_kb_item( name: "ftp/ricoh/dsc_ftpd/detected", value: TRUE );
		guess += "\n- Ricoh DC Software FTP Server";
	}
	if(ContainsString( banner, "Telnet-Ftp Server" )){
		set_kb_item( name: "ftp/telnet_ftp/detected", value: TRUE );
		guess += "\n- Telnet-FTP Server";
	}
	if(IsMatchRegexp( banner, "220[- ]FTP Server ready" )){
		set_kb_item( name: "ftp/ftp_ready_banner/detected", value: TRUE );
		guess += "\n- Various FTP servers like KnFTP or Schneider Electric Quantum Ethernet Module ";
	}
	if(IsMatchRegexp( banner, "220[- ]Ready" )){
		set_kb_item( name: "ftp/ready_banner/detected", value: TRUE );
		guess += "\n- Various FTP servers like Janitza FTP";
	}
	if(ContainsString( banner, "TurboFTP Server" )){
		set_kb_item( name: "ftp/turboftp/detected", value: TRUE );
		guess += "\n- TurboFTP Server";
	}
	if(ContainsString( banner, "BlackMoon FTP Server" )){
		set_kb_item( name: "ftp/blackmoon/detected", value: TRUE );
		guess += "\n- BlackMoon FTP";
	}
	if(ContainsString( banner, "Solar FTP Server" )){
		set_kb_item( name: "ftp/solarftp/detected", value: TRUE );
		guess += "\n- Solar FTP";
	}
	if(ContainsString( banner, "WS_FTP Server" )){
		set_kb_item( name: "ftp/ws_ftp/detected", value: TRUE );
		guess += "\n- WS_FTP Server";
	}
	if(ContainsString( banner, "FTP Utility FTP server" )){
		set_kb_item( name: "ftp/konica/ftp_utility/detected", value: TRUE );
		guess += "\n- Konica Minolta FTP Utility";
	}
	if(ContainsString( banner, "BisonWare BisonFTP server" )){
		set_kb_item( name: "ftp/bisonware/bisonftp/detected", value: TRUE );
		guess += "\n- BisonWare BisonFTP Server";
	}
	if(ContainsString( banner, "Welcome to ColoradoFTP" ) && ContainsString( banner, "www.coldcore.com" )){
		set_kb_item( name: "ftp/coldcore/coloradoftp/detected", value: TRUE );
		guess += "\n- ColoradoFTP";
	}
	if(ContainsString( banner, "FRITZ!Box" ) && ContainsString( banner, "FTP server ready." )){
		set_kb_item( name: "ftp/avm/fritzbox_ftp/detected", value: TRUE );
		guess += "\n- AVM FRITZ!Box FTP";
	}
	if(egrep( string: banner, pattern: "FTP server.*[Vv]ersion (wu|wuftpd)-" )){
		set_kb_item( name: "ftp/wu_ftpd/detected", value: TRUE );
		guess += "\n- WU-FTPD";
	}
	if(ContainsString( banner, "WarFTPd" ) || ContainsString( banner, "WAR-FTPD" )){
		set_kb_item( name: "ftp/war_ftpd/detected", value: TRUE );
		guess += "\n- WarFTPd";
	}
	if(ContainsString( banner, "I'm freeFTPd" )){
		set_kb_item( name: "ftp/free_ftpd/detected", value: TRUE );
		guess += "\n- freeFTPd";
	}
	if(IsMatchRegexp( banner, "220[- ]Browser Ftp Server\\." )){
		set_kb_item( name: "ftp/browser_ftp_server_banner/detected", value: TRUE );
		guess += "\n- Various FTP servers like MySCADA MyPRO";
	}
	if(ContainsString( banner, "Welcome to D-Link's FTP Server" )){
		set_kb_item( name: "ftp/dlink/ftp_server/detected", value: TRUE );
		guess += "\n- Multiple D-Link products like Central WiFiManager";
	}
	if(ContainsString( bannerlo, "pyftpd" )){
		set_kb_item( name: "ftp/pyftpdlib/detected", value: TRUE );
		guess += "\n- pyftpdlib";
	}
	if(ContainsString( banner, "FTP Services for ClearPath MCP" )){
		set_kb_item( name: "ftp/clearpath/mcp/detected", value: TRUE );
		guess += "\n- ClearPath MCP";
	}
	if(ContainsString( bannerlo, "welcome to vibnode." )){
		set_kb_item( name: "ftp/prueftechnik/vibnode/detected", value: TRUE );
		guess += "\n- PRUFTECHNIK VIBNODE";
	}
	if(ContainsString( banner, "Welcome to Pure-FTPd" ) || ContainsString( banner, "Welcome to PureFTPd" ) || ContainsString( help, "Pure-FTPd - http://pureftpd.org" )){
		set_kb_item( name: "ftp/pure_ftpd/detected", value: TRUE );
		guess += "\n- Pure-FTPd";
	}
	if(ContainsString( banner, "FCX STARDOM" )){
		set_kb_item( name: "ftp/yokogawa/stardom/detected", value: TRUE );
		guess += "\n- Yokogawa STARDOM";
	}
	if(IsMatchRegexp( banner, "CP ([0-9\\-]+) (IT )?FTP-Server V([0-9.]+) ready for new user" )){
		set_kb_item( name: "ftp/siemens/simatic_cp/detected", value: TRUE );
		guess += "\n- Siemens SIMATIC CP";
	}
	if(IsMatchRegexp( banner, "220[- ]FreeFloat" ) || ContainsString( banner, "FreeFloat Ftp Server" )){
		set_kb_item( name: "ftp/freefloat/detected", value: TRUE );
		guess += "\n- FreeFloat";
	}
	if(IsMatchRegexp( banner, "220[- ]quickshare ftpd" )){
		set_kb_item( name: "ftp/quickshare/file_share/detected", value: TRUE );
		guess += "\n- QuickShare File Share";
	}
	if(IsMatchRegexp( banner, "220[- ]SpoonFTP" )){
		set_kb_item( name: "ftp/spoonftp/detected", value: TRUE );
		guess += "\n- SpoonFTP";
	}
	if(ContainsString( banner, "Quick 'n Easy FTP Server" )){
		set_kb_item( name: "ftp/quick_n_easy/detected", value: TRUE );
		guess += "\n" + "- Quick 'n Easy FTP Server";
	}
	if(ContainsString( banner, "Powerd by BigFoolCat Ftp Server" ) || IsMatchRegexp( banner, "220[- ]+Welcome to my ftp server" )){
		set_kb_item( name: "ftp/easy_ftp/detected", value: TRUE );
		guess += "\n- Easy~FTP Server";
	}
	if(ContainsString( banner, "Golden FTP Server" )){
		set_kb_item( name: "ftp/golden_tfp/detected", value: TRUE );
		guess += "\n- Golden FTP Server";
	}
	if(IsMatchRegexp( banner, "220[- ]ActiveFax" )){
		set_kb_item( name: "ftp/actfax_ftp/detected", value: TRUE );
		guess += "\n- ActFax FTP Server";
	}
	if(egrep( pattern: ".*heck Point Firewall-1 Secure FTP.*", string: banner )){
		set_kb_item( name: "ftp/fw1ftpd/detected", value: TRUE );
		register_product( cpe: "cpe:/a:checkpoint:firewall-1", location: install, port: port );
		guess += "\n- Check Point Firewall-1";
	}
	if(ContainsString( banner, "Menasoft GrayFTP Server" )){
		set_kb_item( name: "ftp/menasoft/sphereftp/detected", value: TRUE );
		guess += "\n- Menasoft SphereFTP Server";
	}
	if(IsMatchRegexp( banner, "220[- ](AXIS|Axis).*Network Camera" )){
		set_kb_item( name: "ftp/axis/network_camera/detected", value: TRUE );
		guess += "\n- Axis Network Camera";
	}
	if(ContainsString( banner, "ProFTPD" ) || ContainsString( banner, "NASFTPD Turbo station" )){
		set_kb_item( name: "ftp/proftpd/detected", value: TRUE );
		guess += "\n- ProFTPD";
	}
	if(IsMatchRegexp( banner, "^220[- ]bftpd " )){
		set_kb_item( name: "ftp/bftpd/detected", value: TRUE );
		guess += "\n- Bftpd FTP";
	}
	if(ContainsString( banner, "FileZilla Server" )){
		set_kb_item( name: "ftp/filezilla/detected", value: TRUE );
		guess += "\n- FileZilla";
	}
	if(IsMatchRegexp( banner, " FTP server \\(MikroTik .* ready" )){
		set_kb_item( name: "ftp/mikrotik/detected", value: TRUE );
		guess += "\n- MikroTik RouterOS";
	}
	if(ContainsString( banner, "Welcome on" ) && ContainsString( banner, "Gabriel's FTP Server" )){
		set_kb_item( name: "ftp/open-ftpd/detected", value: TRUE );
		guess += "\n- Open-FTPD";
	}
	if(ContainsString( banner, "xlweb FTP server" )){
		set_kb_item( name: "ftp/honeywell/falcon_xl/detected", value: TRUE );
		guess += "\n- Honeywell Falcon XL Web Controller";
	}
	if(IsMatchRegexp( banner, "220[- ]PCMan's FTP Server" )){
		set_kb_item( name: "ftp/pcmans/ftp/detected", value: TRUE );
		guess += "\n" + "-  PCMan's FTP Server";
	}
	if(ContainsString( banner, "Welcome to Seagate Central" )){
		set_kb_item( name: "ftp/seagate/central/detected", value: TRUE );
		guess += "\n- Seagate Central";
	}
	if(IsMatchRegexp( banner, "220[- ]Titan FTP Server " )){
		set_kb_item( name: "ftp/titan/ftp/detected", value: TRUE );
		guess += "\n- Titan FTP Server";
	}
	if(ContainsString( banner, "Minftpd" )){
		set_kb_item( name: "ftp/ftpdmin/detected", value: TRUE );
		guess += "\n- Ftpdmin";
	}
	if(ContainsString( banner, "220 Features p a" ) || ContainsString( banner, "Sami FTP Server" )){
		set_kb_item( name: "ftp/samiftp/detected", value: TRUE );
		guess += "\n- KarjaSoft Sami FTP";
	}
	if(IsMatchRegexp( banner, "Welcome to the (Cisco TelePresence|Codian) MCU" )){
		set_kb_item( name: "ftp/cisco/telepresence/detected", value: TRUE );
		guess += "\n- Cisco TelePresence";
	}
	if(egrep( pattern: ".*icrosoft FTP.*", string: banner )){
		set_kb_item( name: "ftp/microsoft/iis_ftp/detected", value: TRUE );
		guess += "\n- Microsoft IIS FTP Server";
	}
	if(ContainsString( banner, "ManageUPSnet" )){
		set_kb_item( name: "ftp/manageupsnet/detected", value: TRUE );
		guess += "\n- ManageUPSNET FTP";
	}
	if(ContainsString( banner, "Isilon OneFS" )){
		set_kb_item( name: "ftp/emc/isilon_onefs/detected", value: TRUE );
		guess += "\n- EMC Isilon OneFS";
	}
	if(ContainsString( banner, "SurgeFTP" )){
		set_kb_item( name: "ftp/surgeftp/detected", value: TRUE );
		guess += "\n- SurgeFTP";
	}
	if(ContainsString( banner, "GuildFTPd" ) || ContainsString( banner, "GuildFTPD FTP" )){
		set_kb_item( name: "ftp/guildftpd/detected", value: TRUE );
		guess += "\n- GuildFTPd";
	}
	if(ContainsString( banner, "IOS-FTP server" )){
		set_kb_item( name: "ftp/cisco/ios_ftp/detected", value: TRUE );
		guess += "\n- Cisco IOS FTP";
	}
	if(ContainsString( banner, "UNIVERSAL FTP SERVER" )){
		set_kb_item( name: "ftp/teamtek/universal_ftp/detected", value: TRUE );
		guess += "\n- Teamtek Universal FTP";
	}
	if(ContainsString( banner, "BlackJumboDog" )){
		set_kb_item( name: "ftp/blackjumbodog/detected", value: TRUE );
		guess += "\n- BlackJumboDog";
	}
	if(ContainsString( banner, "SunFTP " )){
		set_kb_item( name: "ftp/sunftp/detected", value: TRUE );
		guess += "\n- SunFTP";
	}
	if(ContainsString( banner, "EFTP " )){
		set_kb_item( name: "ftp/eftp/detected", value: TRUE );
		guess += "\n- EFTP";
	}
	if(ContainsString( banner, "ArGoSoft FTP Server" )){
		set_kb_item( name: "ftp/argosoft/ftp/detected", value: TRUE );
		guess += "\n- ArGoSoft FTP";
	}
	if(ContainsString( banner, "GlobalSCAPE Secure FTP Server" )){
		set_kb_item( name: "ftp/globalscape/secure_ftp/detected", value: TRUE );
		guess += "\n- GlobalSCAPE Secure FTP Server";
	}
	if(ContainsString( banner, "HP ARPA FTP" )){
		set_kb_item( name: "ftp/hp/arpa_ftp/detected", value: TRUE );
		guess += "\n- HP ARPA FTP / MPEi/X";
	}
	if(egrep( pattern: ".*RaidenFTPD.*", string: banner )){
		set_kb_item( name: "ftp/raidenftpd/detected", value: TRUE );
		guess += "\n- RaidenFTPD";
	}
	if(ContainsString( banner, "Serv-U FTP Server" )){
		set_kb_item( name: "ftp/serv-u/detected", value: TRUE );
		guess += "\n- Serv-U FTP";
	}
	if(ContainsString( banner, "Flash FTP Server" )){
		set_kb_item( name: "ftp/flash/ftp/detected", value: TRUE );
		guess += "\n- Flash FTP Server";
	}
	if(ContainsString( banner, "PlatinumFTPserver" )){
		set_kb_item( name: "ftp/platinum/ftp/detected", value: TRUE );
		guess += "\n- Platinum FTP";
	}
	if(egrep( pattern: "^220.*RobotFTP" )){
		set_kb_item( name: "ftp/robot/ftp/detected", value: TRUE );
		guess += "\n- RobotFTP";
	}
	if(ContainsString( banner, "220 Wing FTP Server" )){
		set_kb_item( name: "ftp/wing/ftp/detected", value: TRUE );
		guess += "\n- Wing FTP";
	}
	if(ContainsString( banner, "220-Complete FTP server" )){
		set_kb_item( name: "ftp/complete/ftp/detected", value: TRUE );
		guess += "\n- Complete FTP";
	}
	if(IsMatchRegexp( banner, "[vV]xWorks" ) && ContainsString( banner, "FTP server" )){
		set_kb_item( name: "ftp/vxftpd/detected", value: TRUE );
		guess += "\n- VxWorks FTP";
	}
	if(ContainsString( banner, "XLINK" )){
		set_kb_item( name: "ftp/omni-nfs/xlink/detected", value: TRUE );
		guess += "\n- Omni-NFS XLINK";
	}
	if(ContainsString( banner, "httpdx" )){
		set_kb_item( name: "ftp/httpdx/detected", value: TRUE );
		set_kb_item( name: "www_or_ftp/httpdx/detected", value: TRUE );
		guess += "\n- httpdx";
	}
	if(ContainsString( bannerlo, "vsftpd" )){
		set_kb_item( name: "ftp/vsftpd/detected", value: TRUE );
		guess += "\n- vsFTPd";
	}
	if(ContainsString( banner, "tnftpd" )){
		set_kb_item( name: "ftp/tnftpd/detected", value: TRUE );
		guess += "\n- tnftpd";
	}
	if(ContainsString( banner, "Buffy" )){
		set_kb_item( name: "ftp/buffy/detected", value: TRUE );
		guess += "\n- Buffy";
	}
	if(ContainsString( banner, "Data ONTAP" )){
		set_kb_item( name: "ftp/netapp/data_ontap/detected", value: TRUE );
		guess += "\n- NetApp Data ONTAP";
	}
	if(IsMatchRegexp( banner, "NET+OS [0-9.]+ FTP server ready\\." )){
		set_kb_item( name: "ftp/net_os/detected", value: TRUE );
		set_kb_item( name: "ftp/datastream/detected", value: TRUE );
		guess += "\n- NET+OS";
		guess += "\n- DataStream (DS800) Device";
	}
	if(ContainsString( banner, "RICOH" ) && ContainsString( banner, "FTP server" )){
		set_kb_item( name: "ftp/ricoh/printer/detected", value: TRUE );
		guess += "\n- RICOH Printer";
	}
	if(ContainsString( banner, "Lexmark" ) && ContainsString( banner, "FTP Server" )){
		set_kb_item( name: "ftp/lexmark/printer/detected", value: TRUE );
		guess += "\n- Lexmark Printer";
	}
	if(ContainsString( banner, "TOSHIBA" ) && ContainsString( banner, " FTP Server" )){
		set_kb_item( name: "ftp/toshiba/printer/detected", value: TRUE );
		guess += "\n- Toshiba Printer";
	}
	if(ContainsString( banner, "220-You are user number " ) || ContainsString( banner, "220-Local time is now " ) || ContainsString( banner, " users (the maximum) are already logged in, sorry" )){
		set_kb_item( name: "ftp/user_number_local_time_banner/detected", value: TRUE );
		guess += "\n- Various FTP servers (e.g. Zyxel Access Points)";
	}
	if(ContainsString( banner, "Virtual-FTPd (vftpd) ready." )){
		set_kb_item( name: "ftp/vftpd/detected", value: TRUE );
		guess += "\n- Virtual-FTPd";
	}
	if(IsMatchRegexp( banner, "FTP server \\(FirstClass" )){
		set_kb_item( name: "ftp/opentext/firstclass/detected", value: TRUE );
		guess += "\n- OpenText FirstClass";
	}
	if(ContainsString( banner, "220 DrayTek FTP" )){
		set_kb_item( name: "ftp/draytek/detected", value: TRUE );
		guess += "\n- DrayTek Vigor Device";
	}
	if(banner == "220 FTP service ready."){
		set_kb_item( name: "ftp/huawei/vrp/detected", value: TRUE );
		guess += "\n- Huawei Versatile Routing Platform (VRP)";
	}
	if(banner == "220 KONICA MINOLTA FTP server ready."){
		set_kb_item( name: "ftp/konicaminolta/printer/detected", value: TRUE );
		guess += "\n- KONICA MINOLTA Printer";
	}
	if(banner == "220 Welcome to Linksys"){
		set_kb_item( name: "ftp/linksys/detected", value: TRUE );
		guess += "\n- Linksys Device";
	}
	if(IsMatchRegexp( banner, "220 FTP Server \\((ZyWALL )?USG ?(FLEX )?[0-9]+(W?(-VPN)?)?\\)" )){
		set_kb_item( name: "ftp/zyxel_usg/detected", value: TRUE );
		guess += "\n- Zyxel USG Device";
	}
	if(IsMatchRegexp( banner, "220 .*FTP Server \\(OEM FTPD version" )){
		set_kb_item( name: "ftp/epson/printer/detected", value: TRUE );
		guess += "\n- Epson Printer";
	}
	if(IsMatchRegexp( banner, "220 EFI FTP Print server" )){
		set_kb_item( name: "ftp/efi/printer/detected", value: TRUE );
		guess += "\n- EFI Printer System";
	}
	report = "Remote FTP server banner:\n\n" + banner;
	if(strlen( guess ) > 0){
		report += "\n\nThis is probably (a):\n" + guess;
	}
	if(syst && egrep( pattern: "^215 .+", string: syst )){
		report += "\n\nServer operating system information collected via \"SYST\" command:\n\n" + syst;
	}
	if(stat && egrep( pattern: "^211 .+", string: stat )){
		report += "\n\nServer status information collected via \"STAT\" command:\n\n" + stat;
	}
	log_message( port: port, data: report );
}
exit( 0 );

