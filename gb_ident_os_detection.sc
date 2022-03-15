if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108565" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-04-18 09:50:47 +0000 (Thu, 18 Apr 2019)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (ident)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "ident_process_owner.sc", "slident.sc" );
	script_mandatory_keys( "ident/os_banner/available" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc1413" );
	script_tag( name: "summary", value: "Identification Protocol (ident) based Operating System
  (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (ident)";
BANNER_TYPE = "Identification Protocol (ident) Service OS banner";
port = service_get_port( default: 113, proto: "auth" );
os = get_kb_item( "ident/" + port + "/os_banner/os_only" );
concl = get_kb_item( "ident/" + port + "/os_banner/full" );
if(!os || !concl || egrep( string: os, pattern: "^[0-9]+$" )){
	exit( 0 );
}
os = tolower( os );
if( ContainsString( os, "windows" ) || ContainsString( os, "win32" ) ){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "windows", port: port );
}
else {
	if( ContainsString( os, "winxp" ) ){
		os_register_and_report( os: "Microsoft Windows XP", cpe: "cpe:/o:microsoft:windows_xp", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "windows", port: port );
	}
	else {
		if( ContainsString( os, "linux" ) || ContainsString( os, "unix" ) ){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide", port: port );
		}
		else {
			if( ContainsString( os, "sunos" ) ){
				os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide", port: port );
			}
			else {
				if( ContainsString( os, "os/2" ) ){
					os_register_and_report( os: "IBM OS/2", cpe: "cpe:/o:ibm:os2", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide", port: port );
				}
				else {
					if( ContainsString( os, "freebsd" ) ){
						os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide", port: port );
					}
					else {
						if( os == "ios" ){
							os_register_and_report( os: "Apple iOS", cpe: "cpe:/o:apple:iphone_os", banner_type: BANNER_TYPE, banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide", port: port );
						}
						else {
							if(!ContainsString( os, "unknown" ) && !ContainsString( os, "other" )){
								os_register_unknown_banner( banner: concl, banner_type_name: BANNER_TYPE, banner_type_short: "ident_os_banner", port: port );
							}
						}
					}
				}
			}
		}
	}
}
exit( 0 );

