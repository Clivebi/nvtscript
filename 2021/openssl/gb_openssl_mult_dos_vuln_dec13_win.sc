CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112975" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-17 06:07:11 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2013-4353", "CVE-2013-6449" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Multiple DoS Vulnerabilities (CVE-2013-4353, CVE-2013-6449) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A carefully crafted invalid TLS handshake could crash OpenSSL with a NULL pointer exception.
  A malicious server could use this flaw to crash a connecting client. (CVE-2013-4353)

  - A flaw in OpenSSL can cause an application using OpenSSL to crash when using TLS version 1.2.
  (CVE-2013-6449)" );
	script_tag( name: "affected", value: "OpenSSL 1.0.1 through 1.0.1e." );
	script_tag( name: "solution", value: "Update to version 1.0.1f or later." );
	script_xref( name: "URL", value: "https://github.com/openssl/openssl/commit/197e0ea817ad64820789d86711d55ff50d71f631" );
	script_xref( name: "URL", value: "https://github.com/openssl/openssl/commit/ca98926" );
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
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1e" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1e", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
