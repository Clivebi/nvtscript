CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107057" );
	script_version( "2021-03-10T13:54:33+0000" );
	script_cve_id( "CVE-2016-7052" );
	script_tag( name: "last_modification", value: "2021-03-10 13:54:33 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "creation_date", value: "2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "OpenSSL Missing CRL sanity check Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20160926.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to a Denial of Service (DoS) vulnerability." );
	script_tag( name: "insight", value: "OpenSSL suffers from the possibility of DoS attack after a bug fix added to OpenSSL
  1.1.0 but was omitted from OpenSSL 1.0.2i causing a null pointer exception when using CRLs in OpenSSL 1.0.2i." );
	script_tag( name: "impact", value: "Successful exploitation could result in a service crash." );
	script_tag( name: "affected", value: "OpenSSL 1.0.2i." );
	script_tag( name: "solution", value: "OpenSSL 1.0.2i users should upgrade to 1.0.2j." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "1.0.2i" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.2j", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

