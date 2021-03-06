CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806730" );
	script_version( "2021-07-29T12:32:36+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-29 12:32:36 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-11-24 18:49:30 +0530 (Tue, 24 Nov 2015)" );
	script_cve_id( "CVE-2015-0292" );
	script_bugtraq_id( 73228 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL DoS Vulnerability (20150319 - 1) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability existed in previous versions of OpenSSL related
  to the processing of base64 encoded data. Any code path that reads base64 data from an untrusted
  source could be affected (such as the PEM processing routines). Maliciously crafted base 64 data
  could trigger a segmenation fault or memory corruption." );
	script_tag( name: "affected", value: "OpenSSL version 0.9.8 through 0.9.8y, 1.0.0 through 1.0.0l and
  1.0.1 through 1.0.1g." );
	script_tag( name: "solution", value: "Update to version 0.9.8za, 1.0.0m, 1.0.1h or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20150319.txt" );
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
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "0.9.8", test_version2: "0.9.8y" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.8za", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.0.0", test_version2: "1.0.0l" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.0m", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.0.1", test_version2: "1.0.1g" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.1h", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

