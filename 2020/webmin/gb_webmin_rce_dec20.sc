CPE = "cpe:/a:webmin:webmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145090" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-12-23 04:50:26 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-28 21:15:00 +0000 (Mon, 28 Dec 2020)" );
	script_cve_id( "CVE-2020-35606" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Webmin <= 1.979 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "webmin.sc" );
	script_mandatory_keys( "usermin_or_webmin/installed" );
	script_tag( name: "summary", value: "Webmin is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Arbitrary command execution can occur in Webmin. Any user
  authorized for the Package Updates module can execute arbitrary commands with root privileges via
  vectors involving %0A and %0C.

  NOTE: this issue exists because of an incomplete fix for CVE-2019-12840." );
	script_tag( name: "affected", value: "Webmin version 1.979 and prior." );
	script_tag( name: "solution", value: "No known solution is available as of 08th July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.pentest.com.tr/exploits/Webmin-1962-PU-Escape-Bypass-Remote-Command-Execution.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.979" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

