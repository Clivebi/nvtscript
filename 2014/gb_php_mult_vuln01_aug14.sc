CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804820" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-3597", "CVE-2014-3587", "CVE-2014-5120" );
	script_bugtraq_id( 69322, 69325, 69375 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-08-25 20:30:05 +0530 (Mon, 25 Aug 2014)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - Aug14" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59709" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57349" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to:

  - Multiple overflow conditions in the 'php_parserr' function within
  ext/standard/dns.c script.

  - Integer overflow in the 'cdf_read_property_info' function in cdf.c
  within the Fileinfo component.

  - An error in the '_php_image_output_ctx' function within ext/gd/gd_ctx.c
  script as NULL bytes in paths to various image handling functions are not stripped." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to overwrite arbitrary
  files, conduct denial of service attacks or potentially execute arbitrary code." );
	script_tag( name: "affected", value: "PHP version 5.4.x before 5.4.32 and 5.5.x before 5.5.16" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.32 or 5.5.16 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^5\\.[45]" )){
	if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.15" ) || version_in_range( version: vers, test_version: "5.4.0", test_version2: "5.4.31" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.4.32/5.5.16" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

