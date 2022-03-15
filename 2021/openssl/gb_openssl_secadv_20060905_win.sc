CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112931" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2006-4339" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: RSA Signature Forgery (CVE-2006-4339) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to RSA signature forgery." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL, when using an RSA key with exponent 3, removes PKCS-1
  padding before generating a hash, which allows remote attackers to forge a PKCS #1 v1.5 signature
  that is signed by that RSA key and prevents OpenSSL from correctly verifying X.509 and other
  certificates that use PKCS #1." );
	script_tag( name: "affected", value: "OpenSSL 0.9.7 through 0.9.7j and 0.9.8 through 0.9.8b." );
	script_tag( name: "solution", value: "Update to version 0.9.7k, 0.9.8c or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20060905.txt" );
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
if(version_in_range( version: version, test_version: "0.9.7", test_version2: "0.9.7j" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.7k", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "0.9.8", test_version2: "0.9.8b" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.8c", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

