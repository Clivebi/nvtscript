if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900012" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_category( ACT_GATHER_INFO );
	script_name( "Enumerates List of Windows Hotfixes" );
	script_family( "Windows" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsName" );
	script_tag( name: "summary", value: "This script is enumerating the list of all installed Windows hotfixes
  on the remote host and saves the enumerated info into the internal Knowledge Base for later use." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
var location1 = "SOFTWARE\\Microsoft\\Updates";
var location2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix";
var location3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages\\";

var list = registry_enum_keys_with_deep(location1,3);
var list2 = registry_enum_keys_with_deep(location2,3);
var list3 = registry_enum_keys(location3);
if (len(list) || len(list2) || len(list3)){
	set_kb_item( name: "SMB/registry_enumerated", value: TRUE );
}
for item in list{
	if(egrep( pattern: "\\\\(KB|Q|M)[0-9]+", string: item )){
		item = str_replace( find: "\\", replace: "/", string: item );
		set_kb_item( name: "SMB/Registry/HKLM/" + item, value: TRUE );
	}
}

for item in list2{
	if(egrep( pattern: "\\\\(KB|Q|M)[0-9]+", string: item )){
		item = str_replace( find: "\\", replace: "/", string: item );
		set_kb_item( name: "SMB/Registry/HKLM/" + item, value: TRUE );
	}
}

for item in list3 {
	if(egrep( pattern: "[P|p]ackage.?[0-9]*.?for.?KB.*", string: item )){
		path = location3 + item;
		path = str_replace( find: "\\", replace: "/", string: path );
		set_kb_item( name: "SMB/Registry/HKLM/" + path, value: TRUE );
	}
}