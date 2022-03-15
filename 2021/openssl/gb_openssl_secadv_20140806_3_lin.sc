CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117578" );
	script_version( "2021-07-30T07:03:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2014-3509" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL DoS Vulnerability (20140806) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A race condition was found in ssl_parse_serverhello_tlsext. If a
  multithreaded client connects to a malicious server using a resumed session and the server sends
  an ec point format extension, it could write up to 255 bytes to freed memory." );
	script_tag( name: "affected", value: "OpenSSL version 1.0.0 through 1.0.0m and 1.0.1 through 1.0.1h." );
	script_tag( name: "solution", value: "Update to version 1.0.0n, 1.0.1i or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20140806.txt" );
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
if(version_in_range( version: version, test_version: "1.0.0", test_version2: "1.0.0m" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.0n", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1h" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1i", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

