CPE = "cpe:/a:zoom:zoom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118235" );
	script_version( "2021-09-30T13:55:33+0000" );
	script_cve_id( "CVE-2021-33907" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 13:55:33 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-29 13:47:33 +0200 (Wed, 29 Sep 2021)" );
	script_name( "Zoom Client < 5.3.0 RCE Vulnerability - Windows" );
	script_tag( name: "summary", value: "Zoom Client is prone to a remote code execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The application fails to properly validate the certificate
  information used to sign .msi files when performing an update of the client. This could lead to
  remote code execution in an elevated privileged context." );
	script_tag( name: "affected", value: "All versions of the Zoom Client before 5.3.0." );
	script_tag( name: "solution", value: "Update to version 5.3.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_zoom_client_detect_win.sc" );
	script_mandatory_keys( "zoom/client/win/detected" );
	script_xref( name: "URL", value: "https://explore.zoom.us/en/trust/security/security-bulletin" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

