if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107648" );
	script_version( "2021-04-22T11:32:38+0000" );
	script_tag( name: "last_modification", value: "2021-04-22 11:32:38 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-04-24 16:27:28 +0200 (Wed, 24 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Delta Electronics CNCSoft A-Series MLCEditor Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_delta_electronics_cncsoft_a-series_smb_login_detect.sc" );
	script_mandatory_keys( "delta_electronics/cncsoft/a-series/detected", "delta_electronics/cncsoft/a-series/location" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Delta Electronics CNCSoft A-Series
  MLCEditor." );
	script_xref( name: "URL", value: "http://www.deltaww.com/" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(!loc = get_kb_item( "delta_electronics/cncsoft/a-series/location" )){
	exit( 0 );
}
location = loc + "MLCEditor\\";
filename = "MLCEditor.exe";
version = fetch_file_version( sysPath: location, file_name: filename );
if(!version){
	exit( 0 );
}
concluded = "\nVersion: " + version + " fetched from file " + location + filename;
set_kb_item( name: "delta_electronics/cncsoft/a-series/mlceditor/detected", value: TRUE );
register_and_report_cpe( app: "Delta Electronics CNCSoft A-Series MLCEditor", ver: version, concluded: concluded, base: "cpe:/a:deltaww:cncsoft_mlceditor:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
exit( 0 );

