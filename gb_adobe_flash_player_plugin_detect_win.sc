if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107320" );
	script_version( "2021-06-23T06:26:38+0000" );
	script_tag( name: "last_modification", value: "2021-06-23 06:26:38 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-24 11:23:58 +0200 (Tue, 24 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Adobe Flash Player Portable Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "win/lsc/search_portable_apps", "WMI/access_successful" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	script_tag( name: "summary", value: "SMB login and WMI file search based detection of the portable
  Adobe Flash Player variant." );
	script_tag( name: "insight", value: "To enable the search for portable versions of this product you
  need to 'Enable Detection of Portable Apps on Windows' in the 'Options for Local Security Checks'
  (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
if(get_kb_item( "win/lsc/disable_wmi_search" )){
	exit( 0 );
}
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
query = "SELECT Name FROM CIM_DataFile WHERE NOT Path LIKE '%\\\\windows\\\\install%' AND FileName LIKE 'NPSWF%' AND Extension = 'dll'";
fileList = wmi_query( wmi_handle: handle, query: query );
if(ContainsString( fileList, "NTSTATUS" ) || !fileList){
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
detectedList = get_kb_list( "AdobeFlashPlayer/Win/InstallLocations" );
fileList = split( buffer: fileList, keep: FALSE );
for filePath in fileList {
	if(filePath == "Name"){
		continue;
	}
	location = ereg_replace( string: filePath, pattern: "\\\\npswf.*\\.dll", replace: "" );
	if(detectedList && in_array( search: tolower( location ), array: detectedList )){
		continue;
	}
	filePath = ereg_replace( pattern: "\\\\", replace: "\\\\", string: filePath );
	versList = wmi_file_fileversion( handle: handle, filePath: filePath, includeHeader: FALSE );
	if(!versList || !is_array( versList )){
		continue;
	}
	for vers in keys( versList ) {
		if(versList[vers] && version = eregmatch( string: versList[vers], pattern: "^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)" )){
			set_kb_item( name: "adobe/flash_player/detected", value: TRUE );
			set_kb_item( name: "AdobeFlashPlayer/Win/InstallLocations", value: tolower( location ) );
			set_kb_item( name: "AdobeFlashPlayer/Win/Installed", value: TRUE );
			if( ContainsString( location, "system32" ) ){
				base = "cpe:/a:adobe:flash_player:x64:";
				app = "Adobe Flash Player Plugin 64bit";
			}
			else {
				if( ContainsString( location, "syswow64" ) ){
					base = "cpe:/a:adobe:flash_player:";
					app = "Adobe Flash Player Plugin 32bit";
				}
				else {
					if( ContainsString( filePath, "npsfw64" ) ){
						base = "cpe:/a:adobe:flash_player:x64:";
						app = "Adobe Flash Player Plugin 64bit Portable";
					}
					else {
						base = "cpe:/a:adobe:flash_player:";
						app = "Adobe Flash Player Plugin 32bit Portable";
					}
				}
			}
			register_and_report_cpe( app: app, ver: version[1], concluded: versList[vers], base: base, expr: "^([0-9.]+)", insloc: location, regPort: 0, regService: "smb-login" );
		}
	}
}
wmi_close( wmi_handle: handle );
exit( 0 );

