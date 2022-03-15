CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100581" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)" );
	script_bugtraq_id( 35440 );
	script_cve_id( "CVE-2009-2687" );
	script_name( "PHP 'exif_read_data()' JPEG Image Processing Denial Of Service Vulnerability" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35440" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_10.php" );
	script_xref( name: "URL", value: "http://lists.debian.org/debian-security-announce/2009/msg00263.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2009-08/0339.html" );
	script_xref( name: "URL", value: "http://support.avaya.com/css/P8/documents/100072880" );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to cause denial-of-
  service conditions in applications that use the vulnerable function." );
	script_tag( name: "affected", value: "Versions prior to PHP 5.2.10 are affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to a denial-of-service vulnerability in its
  exif_read_data()' function." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(IsMatchRegexp( vers, "^5\\.2" )){
	if(version_is_less( version: vers, test_version: "5.2.10" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.10" );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

