if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107485" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-01-29 14:44:33 +0100 (Tue, 29 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Oracle Application Testing Suite Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Oracle Application Testing Suite." );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/oem/app-test/etest-101273.html" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
key_list = make_list( "SYSTEM\\CurrentControlSet\\Services\\" );
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!appName || !IsMatchRegexp( appName, "Oracle ATS Agent" )){
			continue;
		}
		version = "unknown";
		concluded = appName;
		location = "unknown";
		loc = registry_get_sz( key: key + item, item: "ImagePath" );
		if(loc){
			split = split( buffer: loc, sep: "\\" );
			max = max_index( split ) - 1;
			string = split[max - 2] + "\\" + split[max - 1] + "\\" + split[max];
			location = ereg_replace( string: loc, pattern: string, replace: "" );
			path = location + "\\\\config\\\\version.properties";
			version_info = smb_read_file( fullpath: path, offset: 0, count: 3000 );
			if(version_info){
				versq = eregmatch( pattern: "oracle.version.build=([0-9.]+)", string: version_info );
				if(versq){
					version = versq[1];
					concluded = appName + " " + versq[0];
				}
			}
		}
		set_kb_item( name: "oracle/application_testing_suite/win/detected", value: TRUE );
		register_and_report_cpe( app: "Oracle Application Testing Suite", ver: version, concluded: concluded, base: "cpe:/a:oracle:application_testing_suite:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

