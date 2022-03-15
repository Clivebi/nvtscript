if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113126" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-08 13:28:30 +0100 (Thu, 08 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-25 14:06:00 +0000 (Thu, 25 Apr 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2016-7443", "CVE-2016-7095" );
	script_bugtraq_id( 94121 );
	script_name( "Exponent CMS 2.3 Multiple File Upload Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_exponet_cms_detect.sc" );
	script_mandatory_keys( "ExponentCMS/installed" );
	script_tag( name: "summary", value: "Exponent CMS 2.3 is prone to multiple vulnerabilities due to oversights in the file upload functionality." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities exist:

  Exponent CMS is vulnerable to an attacker uploading a malicious script file using redirection to place
  the script in an unprotected folder, one allowing script execution.

  Exponent CMS allows remote attackers to have unspecified impact via vectors related to uploading files to wrong location." );
	script_tag( name: "affected", value: "Exponent CMS 2.3.0 through 2.3.9" );
	script_tag( name: "solution", value: "Update to Exponent CMS 2.4.0" );
	script_xref( name: "URL", value: "https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.0" );
	exit( 0 );
}
CPE = "cpe:/a:exponentcms:exponent_cms";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.3.0", test_version2: "2.3.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

