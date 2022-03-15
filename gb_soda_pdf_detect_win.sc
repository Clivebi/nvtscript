if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803750" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-09-03 10:35:37 +0530 (Tue, 03 Sep 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Soda PDF Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Soda PDF.

The script logs in via smb, searches for Soda PDF and gets the version
from 'DisplayVersion' string in registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	sodaName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( sodaName, "Soda PDF" )){
		insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!insloc){
			exit( 0 );
		}
		sodaVer = fetch_file_version( sysPath: insloc, file_name: "PDFServerEngine.exe" );
		if(sodaVer){
			set_kb_item( name: "Soda/PDF/Ver/Win", value: sodaVer );
			cpe = build_cpe( value: sodaVer, exp: "^([0-9.]+)", base: "cpe:/a:soda:soda_pdf:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:soda:soda_pdf";
			}
			register_product( cpe: cpe, location: insloc );
			log_message( data: build_detection_report( app: "Soda PDF", version: sodaVer, install: insloc, cpe: cpe, concluded: sodaVer ) );
		}
	}
}

