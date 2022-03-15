CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804241" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2012-1171" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-02-19 16:40:59 +0530 (Wed, 19 Feb 2014)" );
	script_name( "PHP 'open_basedir' Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is in libxml RSHUTDOWN function which allows to bypass open_basedir
  protection mechanism through stream_close method call." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to read arbitrary files." );
	script_tag( name: "affected", value: "PHP versions 5.x.0 to 5.0.5, 5.1.0 to 5.1.6, 5.2.0 to 5.2.17, 5.3.0 to
  5.3.27, 5.4.0 to 5.4.23 and 5.5.0 to 5.5.6." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=802591" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
if(version_in_range( version: phpVer, test_version: "5.0.0", test_version2: "5.0.5" ) || version_in_range( version: phpVer, test_version: "5.1.0", test_version2: "5.1.6" ) || version_in_range( version: phpVer, test_version: "5.2.0", test_version2: "5.2.17" ) || version_in_range( version: phpVer, test_version: "5.3.0", test_version2: "5.3.27" ) || version_in_range( version: phpVer, test_version: "5.4.0", test_version2: "5.4.23" ) || version_in_range( version: phpVer, test_version: "5.5.0", test_version2: "5.5.6" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "N/A" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

