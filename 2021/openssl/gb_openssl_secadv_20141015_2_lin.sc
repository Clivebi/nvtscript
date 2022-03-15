CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117579" );
	script_version( "2021-08-30T12:36:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 12:36:10 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL Multiple Vulnerabilities (20141015) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following flaws exist / mitigation has been implemented:

  - CVE-2014-3566: OpenSSL has added support for TLS_FALLBACK_SCSV to allow applications to block
  the ability for a MITM attacker to force a protocol downgrade. Some client applications (such as
  browsers) will reconnect using a downgraded protocol to work around interoperability bugs in older
  servers. This could be exploited by an active man-in-the-middle to downgrade connections to SSL
  3.0 even if both sides of the connection support higher protocols. SSL 3.0 contains a number of
  weaknesses including POODLE.

  - CVE-2014-3567: When an OpenSSL SSL/TLS/DTLS server receives a session ticket the integrity of
  that ticket is first verified. In the event of a session ticket integrity check failing, OpenSSL
  will fail to free memory causing a memory leak. By sending a large number of invalid session
  tickets an attacker could exploit this issue in a Denial Of Service attack.

  - CVE-2014-3568: When OpenSSL is configured with 'no-ssl3' as a build option, servers could accept
  and complete a SSL 3.0 handshake, and clients could be configured to send them." );
	script_tag( name: "affected", value: "OpenSSL version 0.9.8 through 0.9.8zb, 1.0.0 through 1.0.0n and
  1.0.1 through 1.0.1i." );
	script_tag( name: "solution", value: "Update to version 0.9.8zc, 1.0.0o, 1.0.1j or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20141015.txt" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00" );
	script_xref( name: "URL", value: "https://www.openssl.org/~bodo/ssl-poodle.pdf" );
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
if(version_in_range( version: version, test_version: "0.9.8", test_version2: "0.9.8zb" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.8zc", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.0", test_version2: "1.0.0n" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.0o", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1i" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1j", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

