if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10400" );
	script_version( "2021-08-11T09:39:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 09:39:10 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_name( "Check for SMB accessible registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_dependencies( "netbios_name_get.sc", "smb_login.sc", "smb_nativelanman.sc", "gb_windows_services_start.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/transport", "SMB/name", "SMB/login", "SMB/password" );
	script_exclude_keys( "SMB/samba" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/scanning.html#requirements-on-target-systems-with-microsoft-windows" );
	script_tag( name: "summary", value: "This routine checks if the registry can be accessed remotely via SMB using the login/password
  credentials. If the access is failing a warning is shown." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}

if(IsWindowsHostAccessable()){
	set_kb_item( name: "SMB/registry_access", value: TRUE );
	set_kb_item( name: "SMB_or_WMI/access_successful", value: TRUE );
}
