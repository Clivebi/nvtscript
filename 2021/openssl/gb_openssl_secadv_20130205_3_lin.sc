CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112972" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-17 06:07:11 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-2686" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: TLS 1.1 and 1.2 AES-NI Crash (20130205) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to a denial of service attack." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A flaw in the OpenSSL handling of CBC ciphersuites in TLS 1.1
  and TLS 1.2 on AES-NI supporting platforms can be exploited in a DoS attack." );
	script_tag( name: "affected", value: "OpenSSL 1.0.1 through 1.0.1c." );
	script_tag( name: "solution", value: "Update to version 1.0.1d or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20130205.txt" );
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
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1c" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1d", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

