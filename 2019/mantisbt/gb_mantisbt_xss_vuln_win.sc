CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142792" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-26 09:30:35 +0000 (Mon, 26 Aug 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-04 13:24:00 +0000 (Wed, 04 Sep 2019)" );
	script_cve_id( "CVE-2019-15074" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.21.2 XSS Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Timeline feature in my_view_page.php in MantisBT has a stored cross-site
  scripting (XSS) vulnerability, allowing execution of arbitrary code (if CSP settings permit it) after uploading
  an attachment with a crafted filename. The code is executed for any user having visibility to the issue,
  whenever My View Page is displayed." );
	script_tag( name: "affected", value: "MantisBT versions through 2.21.1." );
	script_tag( name: "solution", value: "Update to version 2.21.2 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=25995" );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "2.21.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.21.2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

