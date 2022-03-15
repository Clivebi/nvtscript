CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150708" );
	script_version( "2021-07-30T07:03:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2014-3513" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL DoS Vulnerability (20141015) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A flaw in the DTLS SRTP extension parsing code allows an
  attacker, who sends a carefully crafted handshake message, to cause OpenSSL to fail to free up to
  64k of memory causing a memory leak. This could be exploited in a Denial Of Service attack. This
  issue affects OpenSSL 1.0.1 server implementations for both SSL/TLS and DTLS regardless of whether
  SRTP is used or configured." );
	script_tag( name: "affected", value: "OpenSSL version 1.0.1 through 1.0.1i.

  Implementations of OpenSSL that have been compiled with OPENSSL_NO_SRTP defined are not affected." );
	script_tag( name: "solution", value: "Update to version 1.0.1j or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20141015.txt" );
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
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1i" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1j", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

