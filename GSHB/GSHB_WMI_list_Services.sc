if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96028" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Get all Windows non System Services, Service start modes and Eventlog Servicestate over WMI (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Get all Windows non System Services,

  Service start modes and Eventlog Servicestate over WMI." );
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
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/EventLogService", value: "error" );
	set_kb_item( name: "WMI/nonSystemServices", value: "error" );
	set_kb_item( name: "WMI/EventLogService/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
handlereg = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/EventLogService", value: "error" );
	set_kb_item( name: "WMI/nonSystemServices", value: "error" );
	set_kb_item( name: "WMI/EventLogService/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
query1 = "select startname, state  from Win32_Service WHERE NOT StartName LIKE \"NT AUTHORITY%\" AND NOT StartName = \"LocalSystem\"";
query2 = "select state  from Win32_Service WHERE NAME = \"eventlog\"";
query3 = "select Name, StartMode from Win32_Service";
nonSystemServices = wmi_query( wmi_handle: handle, query: query1 );
EventLogService = wmi_query( wmi_handle: handle, query: query2 );
ServiceStartmode = wmi_query( wmi_handle: handle, query: query3 );
if(!nonSystemServices){
	nonSystemServices = "None";
}
if(!EventLogService){
	EventLogService = "None";
}
if(!ServiceStartmode){
	ServiceStartmode = "None";
}
set_kb_item( name: "WMI/EventLogService", value: EventLogService );
set_kb_item( name: "WMI/nonSystemServices", value: nonSystemServices );
set_kb_item( name: "WMI/ServiceStartmode", value: ServiceStartmode );
wmi_close( wmi_handle: handle );
wmi_close( wmi_handle: handlereg );
exit( 0 );

