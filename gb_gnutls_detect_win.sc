if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800916" );
	script_version( "$Revision: 13901 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-27 10:33:17 +0100 (Wed, 27 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-03 13:43:16 +0530 (Mon, 03 Feb 2014)" );
	script_name( "GnuTLS Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of GnuTLS on Windows.

  The script logs in via smb, searches for GnuTLS in the registry
  and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		gnuTLSName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( gnuTLSName, "GnuTLS" )){
			gnuTLSVers = registry_get_sz( key: key + item, item: "DisplayVersion" );
			gnuTLSPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!gnuTLSPath){
				gnuTLSPath = "Couldn find the install location from registry";
			}
			if(gnuTLSVers){
				set_kb_item( name: "openssl_or_gnutls/detected", value: TRUE );
				set_kb_item( name: "gnutls/detected", value: TRUE );
				if( ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					register_and_report_cpe( app: "GnuTLS", ver: gnuTLSVers, base: "cpe:/a:gnu:gnutls:x64:", expr: "^([0-9.]+)", insloc: gnuTLSPath, regPort: 0, regService: "smb-login" );
				}
				else {
					register_and_report_cpe( app: "GnuTLS", ver: gnuTLSVers, base: "cpe:/a:gnu:gnutls:", expr: "^([0-9.]+)", insloc: gnuTLSPath, regPort: 0, regService: "smb-login" );
				}
				exit( 0 );
			}
		}
	}
}

