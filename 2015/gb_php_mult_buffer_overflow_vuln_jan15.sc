CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805410" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-8626" );
	script_bugtraq_id( 70928 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-01-06 17:55:40 +0530 (Tue, 06 Jan 2015)" );
	script_name( "PHP Multiple Buffer Overflow Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "PHP is prone to denial of service and arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Improper validation of user supplied input passed to date_from_ISO8601()
    function in xmlrpc.c

  - including a timezone field in a date, leading to improper XML-RPC
    encoding." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "PHP versions 5.2.x before 5.2.7" );
	script_tag( name: "solution", value: "Update to PHP version 5.2.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=45226" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2014/11/06/3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!phpVer = get_app_version( cpe: CPE, port: phpPort )){
	exit( 0 );
}
if(IsMatchRegexp( phpVer, "^5\\.2" )){
	if(version_in_range( version: phpVer, test_version: "5.2.0", test_version2: "5.2.6" )){
		report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.7" );
		security_message( data: report, port: phpPort );
		exit( 0 );
	}
}
exit( 99 );

