if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108443" );
	script_version( "2021-06-23T05:58:47+0000" );
	script_tag( name: "last_modification", value: "2021-06-23 05:58:47 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-20 11:47:59 +0200 (Fri, 20 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Mozilla Firefox Portable Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "win/lsc/search_portable_apps", "WMI/access_successful" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	script_tag( name: "summary", value: "SMB login and WMI file search based detection of Mozilla Firefox
  Portable." );
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
fileList = wmi_file_fileversion( handle: handle, fileName: "firefox", fileExtn: "exe", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
detectedList = get_kb_list( "Firefox/Win/InstallLocations" );
for filePath in keys( fileList ) {
	location = filePath - "\\firefox.exe";
	if(detectedList && in_array( search: tolower( location ), array: detectedList )){
		continue;
	}
	vers = fileList[filePath];
	if(vers && version = eregmatch( string: vers, pattern: "^([0-9]+\\.[0-9]+\\.[0-9]+)" )){
		set_kb_item( name: "Firefox/Win/InstallLocations", value: tolower( location ) );
		set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value: TRUE );
		set_kb_item( name: "Firefox/Linux_or_Win/installed", value: TRUE );
		set_kb_item( name: "mozilla/firefox/windows/detected", value: TRUE );
		set_kb_item( name: "mozilla/firefox/linux_windows/detected", value: TRUE );
		set_kb_item( name: "mozilla/firefox/windows_macosx/detected", value: TRUE );
		set_kb_item( name: "mozilla/firefox/windows_linux_macosx/detected", value: TRUE );
		if( ContainsString( location, "firefox64" ) ){
			cpe = "cpe:/a:mozilla:firefox:x64:";
			set_kb_item( name: "Firefox64/Win/Ver", value: version[1] );
		}
		else {
			cpe = "cpe:/a:mozilla:firefox:";
			set_kb_item( name: "Firefox/Win/Ver", value: version[1] );
		}
		register_and_report_cpe( app: "Mozilla Firefox Portable", ver: version[1], concluded: vers, base: cpe, expr: "^([0-9.]+)", insloc: location, regPort: 0, regService: "smb-login" );
	}
}
exit( 0 );

