if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113307" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2018-12-06 11:50:00 +0100 (Thu, 06 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Omron CX-Server Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "SMB login-based detection of Omron CX-Server." );
	script_xref( name: "URL", value: "https://industrial.omron.eu/en/products/cx-server" );
	exit( 0 );
}
CPE = "cpe:/a:omron:cx-server:";
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
base_key_one = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
base_key_two = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for keypart in nasl_make_list_unique( registry_enum_keys( key: base_key_one ), registry_enum_keys( key: base_key_two ) ) {
	key = base_key_one + keypart;
	if(!registry_key_exists( key: key )){
		key = base_key_two + keypart;
		if(!registry_key_exists( key: key )){
			continue;
		}
	}
	name = registry_get_sz( key: key, item: "DisplayName" );
	if(!IsMatchRegexp( name, "^CX[- ]Server" ) || IsMatchRegexp( name, "Driver" )){
		continue;
	}
	set_kb_item( name: "omron/cx-server/detected", value: TRUE );
	version = "unknown";
	vers = registry_get_sz( key: key, item: "DisplayVersion" );
	if(!isnull( vers ) && vers != ""){
		version = vers;
		set_kb_item( name: "omron/cx-server/version", value: version );
	}
	insloc = registry_get_sz( key: key, item: "InstallLocation" );
	register_and_report_cpe( app: "Omron CX-Server", ver: version, concluded: version, base: CPE, expr: "([0-9.]+)", insloc: insloc, regService: "smb-login" );
	exit( 0 );
}
exit( 0 );

