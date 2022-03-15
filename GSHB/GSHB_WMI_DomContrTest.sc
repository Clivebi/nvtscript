if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96039" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "List Windows AD ClientSiteName (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script List Windows AD ClientSiteName (Windows)." );
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
PORT389 = get_kb_list( "Ports/tcp/389" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/ClientSiteName", value: "error" );
	set_kb_item( name: "WMI/ClientSiteName/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/ClientSiteName", value: "error" );
	set_kb_item( name: "WMI/ClientSiteName/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
if( PORT389 == "1" ){
	query = " select ClientSiteName from Win32_NTDomain";
	ClientSiteName = wmi_query( wmi_handle: handle, query: query );
	ClientSiteName = split( buffer: ClientSiteName, sep: "\n", keep: 0 );
	if( ContainsString( ClientSiteName[1], "(null)|Domain:" ) ) {
		set_kb_item( name: "WMI/ClientSiteName", value: "nodc" );
	}
	else {
		if(!ContainsString( ClientSiteName[1], "(null)|Domain:" )){
			set_kb_item( name: "WMI/ClientSiteName", value: ClientSiteName[1] );
		}
	}
}
else {
	set_kb_item( name: "WMI/ClientSiteName", value: "nodc" );
}
wmi_close( wmi_handle: handle );
exit( 0 );

