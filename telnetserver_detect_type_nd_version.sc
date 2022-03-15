if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10281" );
	script_version( "2021-05-04T10:59:20+0000" );
	script_tag( name: "last_modification", value: "2021-05-04 10:59:20 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Telnet Banner Reporting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Service detection" );
	script_dependencies( "telnet.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_tag( name: "summary", value: "This scripts reports the received banner of a Telnet service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(strlen( banner )){
	if( !ContainsString( tolower( banner ), "login:" ) ){
		set_kb_item( name: "telnet/" + port + "/no_login_banner", value: TRUE );
		set_kb_item( name: "telnet/no_login_banner", value: TRUE );
	}
	else {
		set_kb_item( name: "telnet/" + port + "/login_banner/available", value: TRUE );
		set_kb_item( name: "telnet/login_banner/available", value: TRUE );
	}
	set_kb_item( name: "telnet/banner/available", value: TRUE );
	set_kb_item( name: "ssh_or_telnet/banner/available", value: TRUE );
	if(service_is_unknown( port: port )){
		service_register( port: port, proto: "telnet", message: "A Telnet server seems to be running on this port" );
	}
	if(ContainsString( banner, "User Access Verification" ) && ( ContainsString( banner, "Username:" ) || ContainsString( banner, "cisco" ) )){
		set_kb_item( name: "telnet/cisco/ios/detected", value: TRUE );
		guess += "\n- Cisco IOS";
	}
	if(ContainsString( banner, "Welcome to ZXDSL 831CII" )){
		set_kb_item( name: "telnet/zte/zxdsl_831cii/detected", value: TRUE );
		guess += "\n- ZTE ZXDSL 831CII";
	}
	if(ContainsString( banner, "MikroTik" ) && ContainsString( banner, "Login:" )){
		set_kb_item( name: "telnet/mikrotik/routeros/detected", value: TRUE );
		guess += "\n- MikroTik RouterOS";
	}
	if(ContainsString( banner, "Huawei TE" )){
		set_kb_item( name: "telnet/huawei/te/detected", value: TRUE );
		guess += "\n- Huawei TE Device";
	}
	if(ContainsString( banner, "HP JetDirect" )){
		set_kb_item( name: "telnet/hp/jetdirect/detected", value: TRUE );
		guess += "\n- HP JetDirect Device";
	}
	if(ContainsString( banner, "IQinVision " )){
		set_kb_item( name: "telnet/vicon_industries/network_camera/detected", value: TRUE );
		guess += "\n- Vicon Industries Network Camera";
	}
	if(ContainsString( banner, "Broadband Satellite" ) && ContainsString( banner, "Hughes Network Systems" )){
		set_kb_item( name: "telnet/hughes_network_systems/broadband_satellite_modem/detected", value: TRUE );
		guess += "\n- Hughes Broadband Satellite Modem";
	}
	if(ContainsString( banner, "VxWorks login:" )){
		set_kb_item( name: "telnet/vxworks/detected", value: TRUE );
		guess += "\n- VxWorks Embedded Device";
		fragile = "\n\nNote: Some specific variants of this service (e.g. running on Kronos 4500) are known to be \"fragile\" or slow to ";
		fragile += "respond. If you don\'t get any results for this service please consider to:";
		fragile += "\n- raise the \"time_between_request\" scanner preference";
		fragile += "\n- add \"Services/telnet, " + port + "\" to the \"non_simult_ports\" scanner preference";
	}
	if(ContainsString( banner, "Welcome to NetLinx" )){
		set_kb_item( name: "telnet/netlinx/detected", value: TRUE );
		guess += "\n- NetLinx Controller";
	}
	if(IsMatchRegexp( banner, "Model name\\s*:\\s*MiiNePort " )){
		set_kb_item( name: "telnet/moxa/miineport/detected", value: TRUE );
		guess += "\n- Moxa MiiNePort";
	}
	if(IsMatchRegexp( banner, "Model name\\s*:\\s*MGate " )){
		set_kb_item( name: "telnet/moxa/mgate/detected", value: TRUE );
		guess += "\n- Moxa MGate";
	}
	if(ContainsString( banner, "Please keyin your password" ) && !IsMatchRegexp( banner, "MiiNePort" ) && !IsMatchRegexp( banner, "MGate" ) && eregmatch( pattern: "Model name\\s*:\\s(NPort )?([^ \r\n]+)", string: banner )){
		set_kb_item( name: "telnet/moxa/nport/detected", value: TRUE );
		guess += "\n- Moxa NPort";
	}
	if(ContainsString( banner, "Welcome to V" ) && ( ContainsString( banner, "VibNode" ) || ContainsString( banner, "VIBNODE" ) )){
		set_kb_item( name: "telnet/pruftechnik/vibnode/detected", value: TRUE );
		guess += "\n- PRUFTECHNIK VIBNODE";
	}
	if(ContainsString( banner, "WAC" ) && ContainsString( banner, "Foxit Software" )){
		set_kb_item( name: "telnet/foxit/wac-server/detected", value: TRUE );
		set_kb_item( name: "ssh_or_telnet/foxit/wac-server/detected", value: TRUE );
		guess += "\n- Foxit Software WAC Server";
	}
	if(ContainsString( banner, "Model: ZNID-GPON" )){
		set_kb_item( name: "telnet/zhone/znid_gpon/detected", value: TRUE );
		guess += "\n- ZHONE ZNID GPON Device";
	}
	if(ContainsString( banner, "User:" ) && ( ContainsString( banner, "(GSM7224V2)" ) || ContainsString( banner, "(GSM7224)" ) )){
		set_kb_item( name: "telnet/netgear/prosafe/detected", value: TRUE );
		guess += "\n- NETGEAR ProSAFE Device";
	}
	if(ContainsString( banner, "Hirschmann Automation and Control GmbH" )){
		set_kb_item( name: "telnet/hirschmann/device/detected", value: TRUE );
		guess += "\n- Hirschmann Device";
	}
	if(ContainsString( banner, "Rugged Operating System" ) || ContainsString( banner, "Command Line Interface RUGGEDCOM" )){
		set_kb_item( name: "telnet/siemens/ruggedcom/detected", value: TRUE );
		guess += "\n- Siemens Rugged Operating System/RUGGEDCOM";
	}
	if(ContainsString( banner, "SIMATIC NET" ) || ContainsString( banner, "SCALANCE" )){
		set_kb_item( name: "telnet/siemens/scalance/detected", value: TRUE );
		guess += "\n- Siemens SIMATIC SCALANCE Device";
	}
	if(IsMatchRegexp( banner, "U1900 OS.*on eSpace" )){
		set_kb_item( name: "telnet/huawei/espace/detected", value: TRUE );
		guess += "\n- Huawei eSpace Unified Gateway";
	}
	if(ContainsString( banner, "Fabric OS" )){
		set_kb_item( name: "telnet/brocade/fabric_os/detected", value: TRUE );
		guess += "\n- Brocade Fabric OS";
	}
	if(IsMatchRegexp( banner, "Autonomic Controls" )){
		set_kb_item( name: "telnet/autonomic_controls/device/detected", value: TRUE );
		guess += "\n- Autonomic Controls Device";
	}
	if(IsMatchRegexp( banner, "(Shield|Power)Link" )){
		set_kb_item( name: "telnet/ecessa/shield_power_link/detected", value: TRUE );
		guess += "\n- Ecessa ShieldLink/PowerLink";
	}
	if(ContainsString( banner, "Telemetry Gateway A840" )){
		set_kb_item( name: "telnet/adcon/telemetry_gateway_a840/detected", value: TRUE );
		guess += "\n- Adcon A840 Telemetry Gateway";
	}
	if(ContainsString( banner, "Huawei DP300" )){
		set_kb_item( name: "telnet/huawei/dp300/detected", value: TRUE );
		guess += "\n- Huawei DP300";
	}
	if(ContainsString( banner, "Bay Networks" ) || ( ContainsString( banner, "Passport" ) || ContainsString( banner, "NetLogin:" ) )){
		set_kb_item( name: "telnet/nortel_bay_networks/device/detected", value: TRUE );
		guess += "\n- Nortel Networks (former Bay Networks) Device";
	}
	if(ContainsString( banner, "Annex" )){
		set_kb_item( name: "telnet/nortel_bay_networks/annex/detected", value: TRUE );
		guess += "\n- Nortel Networks (former Bay Networks) Annex";
	}
	if(ContainsString( banner, "@ Userid:" )){
		set_kb_item( name: "telnet/shiva/lanrover/detected", value: TRUE );
		guess += "\n- Shiva LanRover";
	}
	if(ContainsString( banner, "Accelar 1200" )){
		set_kb_item( name: "telnet/bay_networks/accelar_1200/detected", value: TRUE );
		guess += "\n- Bay Networks Accelar 1200 Switch";
	}
	if(ContainsString( banner, "Ctrl-Y" ) || ContainsString( banner, "P Configuration" )){
		set_kb_item( name: "telnet/nortel_networks/baystack/detected", value: TRUE );
		guess += "\n- Nortel Baystack Switch";
	}
	if(ContainsString( banner, "Welcome to P330" )){
		set_kb_item( name: "telnet/avaya_p330/detected", value: TRUE );
		guess += "\n- Avaya P330 Stackable Switch";
	}
	if(ContainsString( banner, "TELNET session" )){
		set_kb_item( name: "telnet/allied/telesyn/detected", value: TRUE );
		guess += "\n- Allied Telesyn Router/Switch";
	}
	if(IsMatchRegexp( banner, "GE.*SNMP/Web Interface" ) && ContainsString( banner, "UPS" )){
		set_kb_item( name: "telnet/ge/snmp_web_iface_adapter/detected", value: TRUE );
		guess += "\n- GE SNMP/Web Interface Adapter";
	}
	if(IsMatchRegexp( banner, "SoftCo OS" )){
		set_kb_item( name: "telnet/huawei/softco/detected", value: TRUE );
		guess += "\n- Huawei SoftCo";
	}
	if(ContainsString( banner, "Welcome to Microsoft Telnet Service" )){
		set_kb_item( name: "telnet/microsoft/telnet_service/detected", value: TRUE );
		guess += "\n- Microsoft Windows Telnet Service";
	}
	if(ContainsString( banner, "KERI-ENET" )){
		set_kb_item( name: "telnet/keri_systems/access_control_system/detected", value: TRUE );
		guess += "\n- Keri Systems Access Control System";
	}
	if(ContainsString( banner, "izon login" )){
		set_kb_item( name: "telnet/izon/ip_camera/detected", value: TRUE );
		guess += "\n- IZON IP Camera";
	}
	if(ContainsString( banner, "SCALANCE X200" )){
		set_kb_item( name: "telnet/siemens/scalance_x200/detected", value: TRUE );
		guess += "\n- Siemens Scalance X200";
	}
	if(ContainsString( banner, "Blackboard LC3000" )){
		set_kb_item( name: "telnet/blackboard/lc3000/detected", value: TRUE );
		guess += "\n- Blackboard LC3000 Laundry Reader";
	}
	if(ContainsString( banner, "insight login" )){
		set_kb_item( name: "telnet/philips/in_sight/detected", value: TRUE );
		guess += "\n- Philips In.Sight";
	}
	if(ContainsString( banner, "Welcome. Type <return>, enter password at # prompt" )){
		set_kb_item( name: "telnet/brother/device/detected", value: TRUE );
		guess += "\n- Multiple Brother Devices";
	}
	if(ContainsString( banner, "ZEM" )){
		set_kb_item( name: "telnet/fingertex/device/detected", value: TRUE );
		guess += "\n- FingerTec Device";
	}
	if(ContainsString( banner, "Polycom Command Shell" ) || ContainsString( banner, "Welcome to ViewStation" ) || ( ContainsString( banner, "Hi, my name is" ) && ContainsString( banner, "Here is what I know about myself" ) )){
		set_kb_item( name: "telnet/polycom/device/detected", value: TRUE );
		guess += "\n- Polycom Device";
	}
	if(ContainsString( banner, "PK5001Z login:" ) || ContainsString( banner, "BCM963268 Broadband Router" )){
		set_kb_item( name: "telnet/zyxel/modem/detected", value: TRUE );
		guess += "\n- ZyXEL PK5001Z or C1100Z Modem";
	}
	if(ContainsString( banner, "===Actiontec xDSL Router===" )){
		set_kb_item( name: "telnet/actiontec/modem/detected", value: TRUE );
		guess += "\n- Actiontec Modem";
	}
	if(IsMatchRegexp( banner, "Welcome to (ZXUN|ZXR10).+ of ZTE Corporation" )){
		set_kb_item( name: "telnet/zte/zxr10/detected", value: TRUE );
		guess += "\n- ZTE ZXR10 Router";
	}
	if(ContainsString( banner, "ManageUPSnet" )){
		set_kb_item( name: "telnet/manageupsnet/detected", value: TRUE );
		guess += "\n- ManageUPSNET UPS / USV";
	}
	if(ContainsString( banner, "TANDBERG Codec Release" )){
		set_kb_item( name: "telnet/tandberg/device/detected", value: TRUE );
		guess += "\n- Tandberg Device";
	}
	if(ContainsString( banner, "Netsynt " )){
		set_kb_item( name: "telnet/netsynt/crd_voice_router/detected", value: TRUE );
		guess += "\n- Netsynt CRD Voice Router";
	}
	if(ContainsString( banner, "pCOWeb login" )){
		set_kb_item( name: "telnet/carel/pcoweb/detected", value: TRUE );
		guess += "\n- CAREL pCOWeb";
	}
	if(ContainsString( banner, "BusyBox" ) || ContainsString( banner, "list of built-in commands" )){
		set_kb_item( name: "telnet/busybox/console/detected", value: TRUE );
		guess += "\n- BusyBox Telnet Console";
	}
	if(ContainsString( banner, "IPmux-2L" )){
		set_kb_item( name: "telnet/ipmux-2l/tdm/detected", value: TRUE );
		guess += "\n- IPmux-2L TDM Pseudowire Access Gateway";
	}
	if(banner == "\r\nToo many users logged in!  Please try again later.\r\n" || IsMatchRegexp( banner, "^\r\n\r\nData ONTAP" )){
		set_kb_item( name: "telnet/netapp/data_ontap/detected", value: TRUE );
		guess += "\n- NetApp Data ONTAP";
	}
	if(ContainsString( banner, "Welcome to the DataStream" )){
		set_kb_item( name: "telnet/datastream/detected", value: TRUE );
		guess += "\n- DataStream (DS800) Device";
	}
	if(ContainsString( banner, "(none) login: " )){
		set_kb_item( name: "telnet/mult_dvr_or_radio/detected", value: TRUE );
		guess += "\n- DVR or Internet Radio Device of multiple vendors (e.g. TELESTAR-DIGITAL GmbH)";
		guess += "\n- HiSilicon Encoder";
	}
	if(ContainsString( banner, "Digitalisierungsbox" )){
		set_kb_item( name: "telnet/digitalisierungsbox/detected", value: TRUE );
		guess += "\n- Digitalisierungsbox STANDARD/BASIC/SMART/PREMIUM";
	}
	if(ContainsString( banner, "SmartLAN login:" )){
		set_kb_item( name: "telnet/inim/smartlan/detected", value: TRUE );
		guess += "\n- Inim SmartLAN";
	}
	if(ContainsString( banner, "| LANCOM" )){
		set_kb_item( name: "telnet/lancom/detected", value: TRUE );
		guess += "\n- LANCOM Device";
	}
	if(ContainsString( banner, "Draytek login:" )){
		set_kb_item( name: "telnet/draytek/detected", value: TRUE );
		guess += "\n- DrayTek Vigor Device";
	}
	if(ContainsString( banner, "Grandstream GXP" )){
		set_kb_item( name: "telnet/grandstream/gxp/detected", value: TRUE );
		guess += "\n- Grandstream GXP Series IP Phone";
	}
	if(ContainsString( banner, "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." ) || ( ContainsString( banner, "Login authentication" ) && ContainsString( banner, "Username:" ) )){
		set_kb_item( name: "telnet/huawei/vrp/detected", value: TRUE );
		guess += "\n- Huawei Versatile Routing Platform (VRP)";
	}
	if(ContainsString( banner, "geneko login:" )){
		set_kb_item( name: "telnet/geneko/router/detected", value: TRUE );
		guess += "\n- Geneko Router";
	}
	if(ContainsString( banner, "xlweb login:" )){
		set_kb_item( name: "telnet/honeywell/excel_web/detected", value: TRUE );
		guess += "\n- Honeywell Excel Web Controller";
	}
	if(IsMatchRegexp( banner, "Welcome to (ZyWALL )?USG ?[0-9]+" )){
		set_kb_item( name: "telnet/zyxel_usg/detected", value: TRUE );
		guess += "\n- Zyxel USG Device";
	}
	report = "Remote Telnet banner:\n\n" + banner;
	if(strlen( guess ) > 0){
		report += "\n\nThis is probably (a):\n" + guess;
	}
	if(strlen( fragile ) > 0){
		report += fragile;
	}
	log_message( port: port, data: report );
}
exit( 0 );

