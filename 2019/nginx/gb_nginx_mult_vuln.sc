CPE = "cpe:/a:nginx:nginx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142802" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 04:48:10 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:36:00 +0000 (Sat, 30 Jan 2021)" );
	script_cve_id( "CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "nginx HTTP/2 Multiple Vulnerablilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_nginx_consolidation.sc" );
	script_mandatory_keys( "nginx/detected" );
	script_tag( name: "summary", value: "nginx is prone to multiple denial of service vulnerabilities in the HTTP/2
  implementation." );
	script_tag( name: "insight", value: "Several security issues were identified in nginx HTTP/2 implementation, which
  might cause excessive memory consumption and CPU usage (CVE-2019-9511, CVE-2019-9513, CVE-2019-9516)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "nginx versions 1.9.5 - 1.17.2." );
	script_tag( name: "solution", value: "Update to version 1.16.1, 1.17.3 or later." );
	script_xref( name: "URL", value: "https://mailman.nginx.org/pipermail/nginx-announce/2019/000249.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "1.9.5", test_version2: "1.16.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.16.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.17", test_version2: "1.17.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.17.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

