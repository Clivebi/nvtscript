if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96011" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "WMI Antivirus Status (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "toolcheck.sc", "smb_login.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Tests WMI AntiVirus Status." );
	exit( 0 );
}
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSSP = get_kb_item( "WMI/WMI_OSSP" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/Antivir", value: "error" );
	set_kb_item( name: "WMI/Antivir/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/Antivir", value: "error" );
	set_kb_item( name: "WMI/Antivir/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
if(OSVER == "5.1" || ( OSVER == "5.2" && ContainsString( "Microsoft(R) Windows(R) XP Professional x64 Edition", OSNAME ) )){
	if( OSSP > 1 ){
		ns = "root\\SecurityCenter";
		query1 = "select displayName from AntiVirusProduct";
		query2 = "select ProductUptoDate from AntiVirusProduct";
		query3 = "select onAccessScanningEnabled from AntiVirusProduct";
		handle = wmi_connect( host: host, username: usrname, password: passwd, ns: ns );
		if(!handle){
			log_message( port: 0, data: "wmi_connect: WMI Connect failed." );
			set_kb_item( name: "WMI/Antivir", value: "error" );
			exit( 0 );
		}
		AntiVir_Name = wmi_query( wmi_handle: handle, query: query1 );
		AntiVir_UpDate = wmi_query( wmi_handle: handle, query: query2 );
		AntiVir_Enable = wmi_query( wmi_handle: handle, query: query3 );
		wmi_close( wmi_handle: handle );
	}
	else {
		AntiVir = "Windows XP <= SP1";
	}
}
if(( OSVER == "6.0" || OSVER == "6.1" || OSVER == "6.2" || OSVER == "6.3" || OSVER == "10.0" ) && OSTYPE == "1"){
	ns = "root\\SecurityCenter2";
	query1 = "select displayName from AntiVirusProduct";
	query2 = "select productState from AntiVirusProduct";
	query3 = "select * from AntiVirusProduct";
	handle = wmi_connect( host: host, username: usrname, password: passwd, ns: ns );
	if(!handle){
		log_message( port: 0, data: "wmi_connect: WMI Connect failed." );
		set_kb_item( name: "WMI/Antivir", value: "error" );
		exit( 0 );
	}
	AntiVir_Name = wmi_query( wmi_handle: handle, query: query1 );
	AntiVir_State = wmi_query( wmi_handle: handle, query: query2 );
	AntiVir_SecurityCenter2 = wmi_query( wmi_handle: handle, query: query3 );
	wmi_close( wmi_handle: handle );
}
if(( OSVER == "5.2" || OSVER == "6.0" || OSVER == "6.1" || OSVER == "6.2" ) && OSTYPE > 1){
	AntiVir = "Server";
}
if(( !ContainsString( "Server", AntiVir ) || !ContainsString( "Windows XP <= SP1", AntiVir ) ) && !AntiVir_Name){
	Antivir = "None";
}
if(!AntiVir && AntiVir_Name){
	Antivir = "Installed";
}
if(!AntiVir_Name){
	AntiVir_Name = "None";
}
if(!AntiVir_UpDate){
	AntiVir_UpDate = "None";
}
if(!AntiVir_Enable){
	AntiVir_Enable = "None";
}
if(!AntiVir_State){
	AntiVir_State = "None";
}
if(!AntiVir_SecurityCenter2){
	AntiVir_SecurityCenter2 = "None";
}
set_kb_item( name: "WMI/Antivir", value: Antivir );
set_kb_item( name: "WMI/Antivir/Name", value: AntiVir_Name );
set_kb_item( name: "WMI/Antivir/UptoDate", value: AntiVir_UpDate );
set_kb_item( name: "WMI/Antivir/Enable", value: AntiVir_Enable );
set_kb_item( name: "WMI/Antivir/State", value: AntiVir_State );
set_kb_item( name: "WMI/Antivir/SecurityCenter2", value: AntiVir_SecurityCenter2 );
exit( 0 );

