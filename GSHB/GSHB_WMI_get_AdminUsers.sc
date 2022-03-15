if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96030" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Get all Windows Admin Users and Groups over WMI (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Get all Windows non System Services
  and Eventlog Servicestate over WMI." );
	exit( 0 );
}
require("wmi_user.inc.sc");
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
	set_kb_item( name: "WMI/LocalWindowsAdminUsers", value: "error" );
	set_kb_item( name: "WMI/LocalWindowsAdminUsers/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/LocalWindowsAdminUsers", value: "error" );
	set_kb_item( name: "WMI/LocalWindowsAdminUsers/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
LOCUSRGRP = wmi_user_groupuser( handle: handle );
LOCUSRGRP = tolower( LOCUSRGRP );
LOCUSRGRP = split( buffer: LOCUSRGRP, sep: "\n", keep: 0 );
LOCUSRS = "";
for(i = 1;i < max_index( LOCUSRGRP );i++){
	LOCUSRGRPinf = split( buffer: LOCUSRGRP[i], sep: "|", keep: 0 );
	LocGrpLst = eregmatch( pattern: "name=\"[^\"]+", string: LOCUSRGRPinf[0] );
	LocGrpLst[0] = ereg_replace( pattern: "name=\"", string: LocGrpLst[0], replace: "" );
	if(ContainsString( LocGrpLst[0], "admin" )){
		LocUsrLst = eregmatch( pattern: "name=\"[^\"]+", string: LOCUSRGRPinf[1] );
		LocUsrLst[0] = ereg_replace( pattern: "name=\"", string: LocUsrLst[0], replace: "" );
		if(!ContainsString( LOCUSRS, LocUsrLst[0] )){
			LOCUSRS = LOCUSRS + LocUsrLst[0] + "|";
		}
	}
}
QLOCUSRS = split( buffer: LOCUSRS, sep: "|", keep: 0 );
for(o = 1;o < max_index( LOCUSRGRP );o++){
	OLOCUSRGRPinf = split( buffer: LOCUSRGRP[o], sep: "|", keep: 0 );
	OLocGrpLst = eregmatch( pattern: "name=\"[^\"]+", string: OLOCUSRGRPinf[0] );
	OLocGrpLst[0] = ereg_replace( pattern: "name=\"", string: OLocGrpLst[0], replace: "" );
	for(Q = 1;Q < max_index( QLOCUSRS );Q++){
		if(ContainsString( OLocGrpLst[0], QLOCUSRS[Q] )){
			OLocUsrLst = eregmatch( pattern: "name=\"[^\"]+", string: OLOCUSRGRPinf[1] );
			OLocUsrLst[0] = ereg_replace( pattern: "name=\"", string: OLocUsrLst[0], replace: "" );
			if(!ContainsString( LOCUSRS, OLocUsrLst[0] )){
				LOCUSRS = LOCUSRS + OLocUsrLst[0] + "|";
			}
		}
	}
}
set_kb_item( name: "WMI/LocalWindowsAdminUsers", value: LOCUSRS );
wmi_close( wmi_handle: handle );
exit( 0 );

