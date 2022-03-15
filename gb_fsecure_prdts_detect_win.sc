if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800355" );
	script_version( "2020-12-07T08:17:42+0000" );
	script_tag( name: "last_modification", value: "2020-12-07 08:17:42 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "F-Secure Multiple Products Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login based detection of F-Secure Anti-Virus
  (for MS Exchange), Workstations and Internet GateKeeper." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Data Fellows\\F-Secure" )){
	exit( 0 );
}
fsavVer = registry_get_sz( key: "SOFTWARE\\Data Fellows\\F-Secure\\Anti-Virus", item: "CurrentVersionEx" );
if(fsavVer){
	set_kb_item( name: "F-Sec/AV/Win/Ver", value: fsavVer );
	register_and_report_cpe( app: "F-secure Anti Virus", ver: fsavVer, base: "cpe:/a:f-secure:f-secure_anti-virus:", expr: "^([0-9]+\\.[0-9]+)" );
}
fsigkVer = registry_get_sz( key: "SOFTWARE\\Data Fellows\\F-Secure\\Anti-Virus for Internet Gateways", item: "CurrentVersion" );
if(fsigkVer){
	set_kb_item( name: "F-Sec/AV/IntGatekeeper/Win/Ver", value: fsigkVer );
	register_and_report_cpe( app: "F-secure Anti Virus Intrnet Gate Keeper", ver: fsigkVer, base: "cpe:/a:f-secure:f-secure_internet_gatekeeper_for_windows:", expr: "^([0-9]+\\.[0-9]+)" );
}
fsavmeVer = registry_get_sz( key: "SOFTWARE\\Data Fellows\\F-Secure\\Anti-Virus Agent for Microsoft Exchange", item: "CurrentVersion" );
if(fsavmeVer){
	set_kb_item( name: "F-Sec/AV/MSExchange/Ver", value: fsavmeVer );
	register_and_report_cpe( app: "F-secure Anti Virus MS Exchange", ver: fsavmeVer, base: "cpe:/a:f-secure:f-secure_anti-virus_for_microsoft_exchange:", expr: "^([0-9]+\\.[0-9]+)" );
}
fsavcsVer = registry_get_sz( key: "SOFTWARE\\Data Fellows\\F-Secure\\FSAVCSIN", item: "CurrentVersion" );
if(fsavcsVer){
	set_kb_item( name: "F-Sec/AV/ClientSecurity/Ver", value: fsavcsVer );
	register_and_report_cpe( app: "F-secure Anti Virus Client Security", ver: fsavcsVer, base: "cpe:/a:f-secure:f-secure_client_security:", expr: "^([0-9]+\\.[0-9]+)" );
}
fsavwsKey = "SOFTWARE\\Data Fellows\\F-Secure\\TNB\\Products\\";
for item in registry_enum_keys( key: fsavwsKey ) {
	fsavwsName = registry_get_sz( key: fsavwsKey + item, item: "ProductName" );
	if(ContainsString( fsavwsName, "F-Secure Anti-Virus for Windows Servers" )){
		fsavwsVer = registry_get_sz( key: fsavwsKey + item, item: "Version" );
		if(fsavwsVer){
			set_kb_item( name: "F-Sec/AV/WindowsServers/Ver", value: fsavwsVer );
			register_and_report_cpe( app: "F-secure Anti Virus Windows Server", ver: fsavwsVer, base: "cpe:/a:f-secure:f-secure_anti-virus_for_windows_servers:", expr: "^([0-9]+\\.[0-9]+)" );
		}
	}
}

