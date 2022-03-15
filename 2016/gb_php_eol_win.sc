CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105888" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-09-15 07:00:00 +0200 (Thu, 15 Sep 2016)" );
	script_name( "PHP End Of Life Detection (Windows)" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://secure.php.net/supported-versions.php" );
	script_xref( name: "URL", value: "https://secure.php.net/eol.php" );
	script_tag( name: "summary", value: "The PHP version on the remote host has reached the end of life and should
  not be used anymore." );
	script_tag( name: "impact", value: "An end of life version of PHP is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "insight", value: "Each release branch of PHP is fully supported for two years from its initial stable release.
  During this period, bugs and security issues that have been reported are fixed and are released in regular point releases.

  After this two year period of active support, each branch is then supported for an additional year for critical security
  issues only. Releases during this period are made on an as-needed basis: there may be multiple point releases, or none,
  depending on the number of reports.

  Once the three years of support are completed, the branch reaches its end of life and is no longer supported." );
	script_tag( name: "solution", value: "Update the PHP version on the remote host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "PHP", cpe: CPE, version: version, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

