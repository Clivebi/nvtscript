CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805690" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2015-2301" );
	script_bugtraq_id( 73037 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)" );
	script_name( "PHP Use-After-Free Remote Code Execution Vulnerability - 01 - Jul15 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to Use-after-free
  vulnerability in the 'phar_rename_archive' function in 'phar_object.c' script" );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "PHP versions before 5.5.22 and 5.6.x before
  5.6.6" );
	script_tag( name: "solution", value: "Update to PHP 5.5.22 or 5.6.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1194747" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-updates/2015-04/msg00002.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
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
	if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.5" )){
		fix = "5.6.6";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( vers, "^5\\.5" )){
	if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.21" )){
		fix = "5.5.22";
		VULN = TRUE;
	}
}
if(VULN){
	report = "Installed Version: " + vers + "\n" + "Fixed Version:     " + fix + "\n";
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

