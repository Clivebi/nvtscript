if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809761" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2016-12-15 15:01:50 +0530 (Thu, 15 Dec 2016)" );
	script_name( "Adobe DNG Converter Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe DNG Converter.

  The script runs a WMI query for 'Adobe DNG Converter.exe' and extracts the
  version information from query result." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
fileList = wmi_file_fileversion( handle: handle, fileName: "Adobe DNG Converter", fileExtn: "exe", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
report = "";
for filePath in keys( fileList ) {
	vers = fileList[filePath];
	if(vers && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		found = TRUE;
		set_kb_item( name: "Adobe/DNG/Converter/Win/Version", value: version[1] );
		cpe = build_cpe( value: version[1], exp: "^([0-9.]+)", base: "cpe:/a:adobe:dng_converter:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:adobe:dng_converter";
		}
		register_product( cpe: cpe, location: filePath );
		report += build_detection_report( app: "Adobe DNG Converter", version: version[1], install: filePath, cpe: cpe, concluded: version[1] ) + "\n\n";
	}
}
if(found){
	log_message( port: 0, data: report );
}
exit( 0 );

