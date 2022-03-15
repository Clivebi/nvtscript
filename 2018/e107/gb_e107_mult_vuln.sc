if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112373" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-11 14:34:11 +0200 (Tue, 11 Sep 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-02 19:05:00 +0000 (Fri, 02 Nov 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2018-15901", "CVE-2018-16381" );
	script_name( "e107 <= 2.1.8 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_tag( name: "summary", value: "E107 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation of the CSRF vulnerability could result
  in an attacker being able to change details such as passwords of users including administrators (CVE-2018-15901).

  A cross-site scripting (XSS) vulnerability exists due to insufficient sanitization in the 'user_loginname'
  parameter (CVE-2018-16381)." );
	script_tag( name: "affected", value: "e107 versions through 2.1.8." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/dhananjay-bajaj/e107_2.1.8_csrf" );
	script_xref( name: "URL", value: "https://github.com/dhananjay-bajaj/E107-v2.1.8-XSS-POC" );
	exit( 0 );
}
CPE = "cpe:/a:e107:e107";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

