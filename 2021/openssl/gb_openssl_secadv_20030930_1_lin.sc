CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112916" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2003-0543", "CVE-2003-0544" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Vulnerabilities in ASN.1 parsing (CVE-2003-0543, CVE-2003-0544) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - An integer overflow could allow remote attackers to cause a denial of service (crash) via an
  SSL client certificate with certain ASN.1 tag values.

  - Incorrect tracking of the number of characters in certain ASN.1 inputs could allow remote
  attackers to cause a denial of service (crash) by sending an SSL client certificate that causes
  OpenSSL to read past the end of a buffer when the long form is used." );
	script_tag( name: "affected", value: "OpenSSL version 0.9.6 through 0.9.6j and 0.9.7 through 0.9.7b." );
	script_tag( name: "solution", value: "Update to version 0.9.6.k, 0.9.7c or later. See the references for
  more details." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20030930.txt" );
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
if(version_in_range( version: version, test_version: "0.9.6", test_version2: "0.9.6j" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.6k", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "0.9.7", test_version2: "0.9.7b" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.7c", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

