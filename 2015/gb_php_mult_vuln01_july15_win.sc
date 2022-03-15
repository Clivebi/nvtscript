CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805688" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-1353", "CVE-2013-6501" );
	script_bugtraq_id( 72267, 72530 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - Jul15 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - an integer overflow vulnerability in PHP's Calendar Extension Conversion
  functions.

  - a flaw in the cache directory that is due to the program creating files for
  the cache in a predictable manner." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to inject WSDL files and have them be used in place of the
  intended file and unexpected data result while using Calendar Extension
  Conversion functions." );
	script_tag( name: "affected", value: "PHP versions through 5.6.7" );
	script_tag( name: "solution", value: "Update to PHP 5.6.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1009103" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1185896" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2015-03/msg00003.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
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
if(IsMatchRegexp( vers, "^5\\.6" )){
	if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.7" )){
		report = "Installed Version: " + vers + "\n" + "Fixed Version:     " + "5.6.8" + "\n";
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

