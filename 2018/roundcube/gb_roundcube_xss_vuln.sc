CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141701" );
	script_version( "2021-06-03T03:24:46+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 03:24:46 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-19 16:11:36 +0700 (Mon, 19 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-13 13:02:00 +0000 (Thu, 13 Dec 2018)" );
	script_cve_id( "CVE-2018-19206" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail < 1.3.8 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "steps/mail/func.inc in Roundcube has XSS via crafted use of <svg><style>, as
demonstrated by an onload attribute in a BODY element, within an HTML attachment." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions 1.3.7 and prior." );
	script_tag( name: "solution", value: "Update to version 1.3.8 or later." );
	script_xref( name: "URL", value: "https://roundcube.net/news/2018/10/26/update-1.3.8-released" );
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
if(version_is_less( version: version, test_version: "1.3.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.8", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

