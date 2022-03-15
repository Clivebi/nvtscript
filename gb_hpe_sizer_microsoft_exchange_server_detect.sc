if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809451" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-10-18 11:53:20 +0530 (Tue, 18 Oct 2016)" );
	script_name( "HPE Sizer for Microsoft Exchange Server Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  HPE Sizer for Microsoft Exchange Server.

  The script logs in via smb, searches for 'HPE Sizer for Microsoft Exchange Server'
  in the registry, gets version and installation path information from the
  registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
for item in registry_enum_keys( key: key ) {
	hpName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( hpName, "HPE Sizer for Microsoft Exchange Server" )){
		hpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(hpVer){
			hpPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!hpPath){
				hpPath = "Couldn find the install location from registry";
			}
			set_kb_item( name: "HPE/sizer/microsoft/exchange/server", value: hpVer );
			if(ContainsString( hpName, "Exchange Server 2010" )){
				register_and_report_cpe( app: hpName, ver: hpVer, base: "cpe:/a:hp:sizer_for_microsoft_exchange_server_2010:", expr: "^([0-9.]+)", insloc: hpPath );
			}
			if(ContainsString( hpName, "Exchange Server 2013" )){
				register_and_report_cpe( app: hpName, ver: hpVer, base: "cpe:/a:hp:sizer_for_microsoft_exchange_server_2013:", expr: "^([0-9.]+)", insloc: hpPath );
			}
			if(ContainsString( hpName, "Exchange Server 2016" )){
				register_and_report_cpe( app: hpName, ver: hpVer, base: "cpe:/a:hp:sizer_for_microsoft_exchange_server_2016:", expr: "^([0-9.]+)", insloc: hpPath );
			}
		}
	}
}
exit( 0 );

