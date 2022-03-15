CPE = "cpe:/a:zoom:zoom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108739" );
	script_version( "2021-09-30T13:55:33+0000" );
	script_cve_id( "CVE-2020-11469", "CVE-2020-11470" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-30 13:55:33 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-07 13:46:00 +0000 (Tue, 07 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-06 08:11:24 +0000 (Mon, 06 Apr 2020)" );
	script_name( "Zoom Client Multiple Vulnerabilities (Apr 2020) - Mac OS X" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_zoom_client_detect_macosx.sc" );
	script_mandatory_keys( "zoom/client/mac/detected" );
	script_xref( name: "URL", value: "https://support.zoom.us/hc/en-us/articles/201361963-New-Updates-for-macOS" );
	script_xref( name: "URL", value: "https://objective-see.com/blog/blog_0x56.html" );
	script_tag( name: "summary", value: "Zoom Client is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Zoom Client is prone to multiple vulnerabilities where a
  malicious party with local access could:

  - CVE-2020-11469: tamper with the Zoom installer to gain additional privileges to the computer

  - CVE-2020-11470: gain access to a user's webcam and microphone" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Zoom Client before version 4.6.9 (19273.0402) on Mac OS X." );
	script_tag( name: "solution", value: "Update to version 4.6.9 (19273.0402) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.6.919273.0402" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.6.9 (19273.0402)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

