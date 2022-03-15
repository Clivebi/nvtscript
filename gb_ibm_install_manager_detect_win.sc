if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801010" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IBM Installation Manager Version Detection (Windows)" );
	script_tag( name: "summary", value: "The script detects the installed IBM Installation Manager version.

  The script logs in via smb, searches for IBM Installation Manager in the
  registry and gets the version from 'version' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
checkduplicate = "";
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\IBM\\Installation Manager" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\IBM\\Installation Manager",
			 "SOFTWARE\\Wow6432Node\\IBM\\Installation Manager" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	iimVer = registry_get_sz( key: key, item: "version" );
	insloc = registry_get_sz( key: key, item: "appDataLocation" );
	if(iimVer != NULL){
		if(ContainsString( checkduplicate, iimVer + ", " )){
			continue;
		}
		checkduplicate += iimVer + ", ";
		set_kb_item( name: "IBM/InstallMang/Win/Ver", value: iimVer );
		cpe = build_cpe( value: iimVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:installation_manager:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:ibm:installation_manager";
		}
		if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
			set_kb_item( name: "IBM/InstallMang64/Win/Ver", value: iimVer );
			cpe = build_cpe( value: iimVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:installation_manager:x64:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:ibm:installation_manager:x64";
			}
		}
		register_product( cpe: cpe, location: insloc );
		log_message( data: build_detection_report( app: "IBM Installatin Manager", version: iimVer, install: insloc, cpe: cpe, concluded: iimVer ) );
	}
}

