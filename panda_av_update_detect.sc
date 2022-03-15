if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102048" );
	script_version( "$Revision: 12974 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Panda Antivirus Update Detect" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Service detection" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_panda_prdts_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Panda/Products/Installed" );
	script_tag( name: "summary", value: "Extracts date of the last update for Panda Antivirus software, from the
  Titanium.ini file and stores it to KB." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Panda Software" )){
	exit( 0 );
}
key = "SOFTWARE\\Panda Software\\";
for item in registry_enum_keys( key: key ) {
	if(ContainsString( item, "Panda Internet Security" )){
		paths[0] = registry_get_sz( key: key + item, item: "DIR" );
	}
	if(ContainsString( item, "Panda Global Protection" )){
		paths[1] = registry_get_sz( key: key + item, item: "DIR" );
	}
	if(ContainsString( item, "Panda Antivirus" )){
		paths[2] = registry_get_sz( key: key + item, item: "DIR" );
	}
}
for(i = 0;i < 3;i++){
	if(paths[i]){
		last_update = smb_read_file( fullpath: paths[i] + "\\Titanium.ini", offset: 0, count: 1000 );
		last_update = egrep( pattern: "^PavSigDate=(.*)$", string: last_update );
		last_update = ereg_replace( pattern: "^PavSigDate=(.*)$", replace: "\\1", string: last_update );
		last_update = last_update - NASLString( "\\r\\n" );
		if(!last_update){
			log_message( data: "Could not find last date of signature base update in file Titanium.ini" );
			exit( 0 );
		}
		set_kb_item( name: "Panda/LastUpdate/Available", value: TRUE );
		if(i == 0){
			set_kb_item( name: "Panda/InternetSecurity/LastUpdate", value: last_update );
		}
		if(i == 1){
			set_kb_item( name: "Panda/GlobalProtect/LastUpdate", value: last_update );
		}
		if(i == 2){
			set_kb_item( name: "Panda/AntiVirus/LastUpdate", value: last_update );
		}
	}
}

