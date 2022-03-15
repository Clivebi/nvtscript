if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80038" );
	script_version( "$Revision: 10390 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-04 08:46:11 +0200 (Wed, 04 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Norton Anti Virus Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security" );
	script_family( "Windows" );
	script_dependencies( "smb_enum_services.sc", "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "solution", value: "Make sure NAV is installed, running and using the latest VDEFS." );
	script_tag( name: "summary", value: "This plugin checks that the remote host has Norton Antivirus installed and
  properly running, and makes sure that the latest Vdefs are loaded." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
func check_database_version(  ){
	var key, item, key_h, value, path, vers;
	key = "SOFTWARE\\Symantec\\SharedDefs\\";
	item = "DEFWATCH_10";
	if(registry_key_exists( key: key )){
		value = registry_get_sz( item: item, key: key );
		if( value ) {
			vers = value;
		}
		else {
			item = "NAVCORP_70";
			value = registry_get_sz( item: item, key: key );
			if( value ) {
				vers = value;
			}
			else {
				item = "NAVNT_50_AP1";
				value = registry_get_sz( item: item, key: key );
				if( value ) {
					vers = value;
				}
				else {
					item = "AVDEFMGR";
					value = registry_get_sz( item: item, key: key );
					if( !value ){
						return NULL;
					}
					else {
						vers = value;
					}
				}
			}
		}
	}
	key = "SOFTWARE\\Symantec\\InstalledApps\\";
	item = "AVENGEDEFS";
	if(registry_key_exists( key: key )){
		value = registry_get_sz( item: item, key: key );
		if(value){
			path = value;
		}
	}
	if(!path || !vers){
		return NULL;
	}
	vers = substr( vers, strlen( path ) + 1, strlen( vers ) - 5 );
	if( vers ){
		return vers;
	}
	else {
		return NULL;
	}
}
func check_product_version( reg ){
	var key, item, key_h, value;
	key = reg;
	item = "version";
	if(registry_key_exists( key: key )){
		value = registry_get_sz( item: item, key: key );
		if(value){
			return value;
		}
	}
	return NULL;
}
value = NULL;
key = "SOFTWARE\\Symantec\\InstalledApps\\";
item = "NAVNT";
if(registry_key_exists( key: key )){
	value = registry_get_sz( item: "SAVCE", key: key );
	if(!value){
		value = registry_get_sz( item: item, key: key );
		if(!value){
			item = "SAVCE";
			value = registry_get_sz( item: item, key: key );
		}
	}
}
if(!value || isnull( value )){
	exit( 0 );
}
set_kb_item( name: "Antivirus/Norton/installed", value: TRUE );
current_database_version = check_database_version();
services = get_kb_item( "SMB/svcs" );
if(services){
	if( ( !ContainsString( services, "Norton AntiVirus" ) ) && ( !ContainsString( services, "Symantec AntiVirus" ) ) && ( !ContainsString( services, "SymAppCore" ) ) ) {
		running = 0;
	}
	else {
		running = 1;
	}
}
product_version = check_product_version( reg: "SOFTWARE\\Symantec\\Norton AntiVirus" );
if(!product_version || isnull( product_version )){
	exit( 0 );
}
warning = 0;
report = "
The remote host has the Norton Antivirus installed. It has been
fingerprinted as :

";
report += "Norton/Symantec Antivirus " + product_version + "
DAT version : " + current_database_version + "

";
virus = "20080923";
if(current_database_version && current_database_version > 0){
	if(int( current_database_version ) < ( int( virus ) - 1 )){
		report += "The remote host has an out-dated version of the Norton
  virus database. Last version is " + virus + "

  ";
		warning = 1;
	}
}
if(services && !running){
	report += "The remote Norton AntiVirus is not running.

";
	warning = 1;
}
if( warning ){
	report += "As a result, the remote host might be infected by viruses received by
email or other means.";
	security_message( port: 0, data: report );
}
else {
	set_kb_item( name: "Antivirus/Norton/description", value: report );
}

