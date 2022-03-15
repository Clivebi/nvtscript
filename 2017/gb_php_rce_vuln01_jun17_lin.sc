CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810954" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2016-4473" );
	script_bugtraq_id( 98999 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-16 12:47:00 +0000 (Fri, 16 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-06-20 15:46:19 +0530 (Tue, 20 Jun 2017)" );
	script_name( "PHP Remote Code Execution Vulnerability-01 Jun17 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in
  '/ext/phar/phar_object.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary code in the context of the user running
  the affected application. Failed exploit attempts will likely cause a
  denial-of-service condition." );
	script_tag( name: "affected", value: "PHP versions 7.0.7 and 5.6.x on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 7.0.8 or 5.6.23
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1347772" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2016-10/msg00007.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^5\\.6" ) ){
	if(version_is_less( version: vers, test_version: "5.6.23" )){
		fix = "5.6.23";
	}
}
else {
	if(IsMatchRegexp( vers, "^7\\.0" )){
		if(version_is_less( version: vers, test_version: "7.0.8" )){
			fix = "7.0.8";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

