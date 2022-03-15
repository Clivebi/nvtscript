CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805660" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-4026", "CVE-2015-4025", "CVE-2015-4024", "CVE-2015-4022", "CVE-2015-4021" );
	script_bugtraq_id( 75056, 74904, 74903, 74902, 74700 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-06-16 18:45:49 +0530 (Tue, 16 Jun 2015)" );
	script_name( "PHP Multiple Vulnerabilities - 02 - Jun15 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Algorithmic complexity vulnerability in the 'multipart_buffer_headers'
    function in main/rfc1867.c script in PHP.

  - 'pcntl_exec' implementation in PHP truncates a pathname upon encountering a
    \\x00 character.

  - Integer overflow in the 'ftp_genlist' function in ext/ftp/ftp.c script in PHP.

  - The 'phar_parse_tarfile' function in ext/phar/tar.c script in PHP does not
    verify that the first character of a filename is different from the
    \\0 character." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service, bypass intended extension
  restrictions and access  and execute files or directories with unexpected
  names via crafted dimensions and remote FTP servers to execute arbitrary code." );
	script_tag( name: "affected", value: "PHP versions before 5.4.41, 5.5.x before
  5.5.25, and 5.6.x before 5.6.9" );
	script_tag( name: "solution", value: "Update to PHP 5.4.41 or 5.5.25 or 5.6.9
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=69085" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2015/06/01/4" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
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
if(IsMatchRegexp( vers, "^5\\.5" )){
	if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.24" )){
		fix = "5.5.25";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( vers, "^5\\.6" )){
	if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.8" )){
		fix = "5.6.9";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( vers, "^5\\.4" )){
	if(version_is_less( version: vers, test_version: "5.4.41" )){
		fix = "5.4.41";
		VULN = TRUE;
	}
}
if(VULN){
	report = "Installed Version: " + vers + "\n" + "Fixed Version:     " + fix + "\n";
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

