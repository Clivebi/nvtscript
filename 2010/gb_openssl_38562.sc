CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100527" );
	script_tag( name: "creation_date", value: "2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)" );
	script_tag( name: "last_modification", value: "2021-03-10 13:54:33 +0000 (Wed, 10 Mar 2021)" );
	script_bugtraq_id( 38562 );
	script_cve_id( "CVE-2009-3245" );
	script_version( "2021-03-10T13:54:33+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "OpenSSL 'bn_wexpend()' Error Handling Unspecified Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38562" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssl_consolidation.sc" );
	script_mandatory_keys( "openssl/detected" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more
  information." );
	script_tag( name: "summary", value: "OpenSSL is prone to an unspecified vulnerability in bn_wexpend()." );
	script_tag( name: "affected", value: "OpenSSL versions prior to OpenSSL 0.9.8m are vulnerable." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
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
if(IsMatchRegexp( vers, "^0\\.9\\." ) && version_is_less( version: vers, test_version: "0.9.8m" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.8m", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

