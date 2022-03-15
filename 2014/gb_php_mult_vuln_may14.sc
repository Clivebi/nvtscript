CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804291" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2013-7226", "CVE-2013-7327", "CVE-2013-7328", "CVE-2014-2020" );
	script_bugtraq_id( 65533, 65676, 65656, 65668 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-09 09:47:32 +0530 (Fri, 09 May 2014)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - May14" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1065108" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Integer overflow in the 'gdImageCrop' function within ext/gd/gd.c script.

  - Improper data types check as using string or array data type in place of
  a numeric data type within ext/gd/gd.c script.

  - Multiple integer signedness errors in the 'gdImageCrop' function within
  ext/gd/gd.c script.

  - Some NULL pointer dereference errors related to the 'imagecrop' function
  implementation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
  service, gain sensitive information and have some other unspecified impacts." );
	script_tag( name: "affected", value: "PHP version 5.5.x before 5.5.9" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.9 or later." );
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
if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.5.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

