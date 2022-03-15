CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146726" );
	script_version( "2021-09-29T08:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 08:01:30 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-17 11:51:44 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-27 19:09:00 +0000 (Mon, 27 Sep 2021)" );
	script_cve_id( "CVE-2021-34798", "CVE-2021-39275", "CVE-2021-40438" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server < 2.4.49 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-34798: NULL pointer dereference in httpd core

  - CVE-2021-39275: ap_escape_quotes buffer overflow

  - CVE-2021-40438: mod_proxy SSRF" );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.48 and prior." );
	script_tag( name: "solution", value: "Update to version 2.4.49 or later." );
	script_xref( name: "URL", value: "https://httpd.apache.org/security/vulnerabilities_24.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.4.49" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.49", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

