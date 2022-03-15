CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806746" );
	script_version( "2021-07-29T13:31:06+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-29 13:31:06 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-12-01 09:41:47 +0530 (Tue, 01 Dec 2015)" );
	script_cve_id( "CVE-2015-1788" );
	script_bugtraq_id( 75158 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL Denial of Service Vulnerability (20150611 - 1) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When processing an ECParameters structure OpenSSL enters an
  infinite loop if the curve specified is over a specially malformed binary polynomial field. This
  can be used to perform denial of service against any system which processes public keys,
  certificate requests or certificates. This includes TLS clients and TLS servers with client
  authentication enabled." );
	script_tag( name: "affected", value: "OpenSSL version 0.9.8 through 0.9.8r, 1.0.0 through 1.0.0d,
  1.0.1 through 1.0.1m and 1.0.2 through 1.0.2a." );
	script_tag( name: "solution", value: "Update to version 0.9.8s, 1.0.0e, 1.0.1n, 1.0.2b or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20150611.txt" );
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
if(version_in_range( version: vers, test_version: "0.9.8", test_version2: "0.9.8r" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.8s", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.0.0", test_version2: "1.0.0d" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.0e", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.0.1", test_version2: "1.0.1m" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.1n", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.0.2", test_version2: "1.0.2a" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.2b", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

