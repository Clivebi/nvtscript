CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112938" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-0891", "CVE-2008-1672" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Multiple Vulnerabilities (20080528) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A flaw in the handling of server name extension data. If OpenSSL has been compiled using the
  non-default TLS server name extensions, a remote  attacker could send a carefully crafted packet
  to a server application using OpenSSL and cause it to crash. (CVE-2008-0891)

  - A flaw if the 'Server Key exchange message' is omitted from a TLS handshake. If a client
  connects to a malicious server with particular cipher suites, the server could cause the client
  to crash. (CVE-2008-1672)" );
	script_tag( name: "affected", value: "OpenSSL 0.9.8f through 0.9.8g." );
	script_tag( name: "solution", value: "Update to version 0.9.8h or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20080528.txt" );
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
if(version_in_range( version: version, test_version: "0.9.8f", test_version2: "0.9.8g" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.8h", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

