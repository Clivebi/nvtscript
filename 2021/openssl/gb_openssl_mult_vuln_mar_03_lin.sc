CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112913" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2003-0131", "CVE-2003-0147" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Multiple Vulnerabilities (CVE-2003-0131, CVE-2003-0147) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - The SSL and TLS components for OpenSSL allow remote attackers to perform an unauthorized RSA
  private key operation via a modified Bleichenbacher attack that uses a large number of SSL or TLS
  connections using PKCS #1 v1.5 padding that cause OpenSSL to leak information regarding the
  relationship between ciphertext and the associated plaintext, aka the 'Klima-Pokorny-Rosa attack'.

  - OpenSSL does not use RSA blinding by default, which allows local and remote attackers to obtain
  the server's private key by determining factors using timing differences on (1) the number of
  extra reductions during Montgomery reduction, and (2) the use of different integer multiplication
  algorithms ('Karatsuba' and normal)." );
	script_tag( name: "affected", value: "OpenSSL version 0.9.6 through 0.9.6i and 0.9.7 through 0.9.7a." );
	script_tag( name: "solution", value: "Update to version 0.9.6.j, 0.9.7b or later. See the references for
  more details." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20030317.txt" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20030319.txt" );
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
if(version_in_range( version: version, test_version: "0.9.6", test_version2: "0.9.6i" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.6j", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "0.9.7", test_version2: "0.9.7a" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.7b", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

