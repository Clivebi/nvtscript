CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108850" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-13 12:50:26 +0000 (Thu, 13 Aug 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-24 18:15:00 +0000 (Thu, 24 Sep 2020)" );
	script_cve_id( "CVE-2020-16145" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail Multiple XSS Vulnerabilities - Aug20" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - cross-site scripting (XSS) via HTML messages with malicious svg content (CVE-2020-16145)

  - cross-site scripting (XSS) via HTML messages with malicious math content" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions before 1.2.12, 1.3.15 and 1.4.8." );
	script_tag( name: "solution", value: "Update to version 1.2.12, 1.3.15 and 1.4.8 or later." );
	script_xref( name: "URL", value: "https://roundcube.net/news/2020/08/10/security-updates-1.4.8-1.3.15-and-1.2.12" );
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
if(version_is_less( version: version, test_version: "1.2.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.3", test_version2: "1.3.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.4", test_version2: "1.4.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
