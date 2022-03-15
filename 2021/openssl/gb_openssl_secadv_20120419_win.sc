CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112962" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-16 10:54:11 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2110" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: ASN1 BIO Vulnerability (20120419) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to an exploitable vulnerability in the
  function asn1_d2i_read_bio." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Any application which uses BIO or FILE based functions to read
  untrusted DER format data is vulnerable. Affected functions are of the form d2i_*_bio or
  d2i_*_fp, for example d2i_X509_bio or d2i_PKCS12_fp.

  Applications using the memory based ASN1 functions (d2i_X509, d2i_PKCS12 etc)
  are not affected. In particular the SSL/TLS code of OpenSSL is *not* affected.

  Applications only using the PEM routines are not affected.

  S/MIME or CMS applications using the built in MIME parser SMIME_read_PKCS7 or
  SMIME_read_CMS *are* affected.

  The OpenSSL command line utility is also affected if used to process untrusted
  data in DER format.

  Note: although an application using the SSL/TLS portions of OpenSSL is not
  automatically affected it might still call a function such as d2i_X509_bio on
  untrusted data and be vulnerable." );
	script_tag( name: "affected", value: "OpenSSL 0.9.8 through 0.9.8u and 1.0.0 through 1.0.0g and 1.0.1." );
	script_tag( name: "solution", value: "Update to version 0.9.8v, 1.0.0i, 1.0.1a or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20120419.txt" );
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
if(version_in_range( version: version, test_version: "0.9.8", test_version2: "0.9.8u" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.8v", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.0", test_version2: "1.0.0g" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.0i", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "1.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1a", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

