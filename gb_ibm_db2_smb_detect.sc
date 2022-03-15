if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900218" );
	script_version( "2021-08-11T09:39:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 09:39:10 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IBM Db2 Detection (SMB)" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script performs a SMB based detection of IBM Db2 Server." );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	if(IsMatchRegexp( registry_get_sz( key: key + item, item: "Publisher" ), "IBM" )){
		appName = registry_get_sz( item: "DisplayName", key: key + item );
		if(ContainsString( appName, "DB2" )){
			concluded = "Registry Key:   " + key + item + "\n";
			concluded += "DisplayName:    " + appName;
			location = "unknown";
			version = "unknown";
			set_kb_item( name: "ibm/db2/detected", value: TRUE );
			loc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(loc){
				location = loc;
			}
			ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!isnull( ver )){
				version = ver;
				concluded += "\nDisplayVersion: " + version;
			}
			set_kb_item( name: "ibm/db2/smb/0/version", value: version );
			set_kb_item( name: "ibm/db2/smb/0/concluded", value: concluded );
			set_kb_item( name: "ibm/db2/smb/0/location", value: loc );
			exit( 0 );
		}
	}
}
exit( 0 );

