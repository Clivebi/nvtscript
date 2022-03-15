CPE = "cpe:/a:zoom:zoom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108740" );
	script_version( "2021-09-30T13:55:33+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 13:55:33 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-04-06 08:11:24 +0000 (Mon, 06 Apr 2020)" );
	script_name( "Zoom Client Password Hash Disclosure Vulnerability (Apr 2020) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_zoom_client_detect_win.sc" );
	script_mandatory_keys( "zoom/client/win/detected" );
	script_xref( name: "URL", value: "https://support.zoom.us/hc/en-us/articles/201361953-New-Updates-for-Windows" );
	script_xref( name: "URL", value: "https://twitter.com/hackerfantastic/status/1245148192037011460" );
	script_tag( name: "summary", value: "Zoom Client is leaking a user's hashed password." );
	script_tag( name: "insight", value: "A malicious party could use UNC links to leak a user's hashed
  password." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Zoom Client before version 4.6.9 (19253.0401) on Windows." );
	script_tag( name: "solution", value: "Update to version 4.6.9 (19253.0401) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.6.919253.0401" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.6.9 (19253.0401)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

