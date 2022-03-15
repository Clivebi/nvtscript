CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112929" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2005-2969" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Man in the Middle Attack (CVE-2005-2969) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to a man in the middle attack." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The SSL/TLS server implementation in OpenSSL, when using the
  SSL_OP_MSIE_SSLV2_RSA_PADDING option, disables a verification step that is required for preventing
  protocol version rollback attacks, which allows remote attackers to force a client and server to
  use a weaker protocol than needed via a man-in-the-middle attack." );
	script_tag( name: "affected", value: "OpenSSL 0.9.7 through 0.9.7g and 0.9.8." );
	script_tag( name: "solution", value: "Update to version 0.9.7h, 0.9.8a or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20051011.txt" );
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
if(version_in_range( version: version, test_version: "0.9.7", test_version2: "0.9.7g" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.7h", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "0.9.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.8a", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

