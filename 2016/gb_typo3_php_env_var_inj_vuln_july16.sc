CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808272" );
	script_version( "2020-11-12T09:56:04+0000" );
	script_cve_id( "CVE-2016-5385" );
	script_bugtraq_id( 91821 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-12 09:56:04 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-07-27 10:28:48 +0530 (Wed, 27 Jul 2016)" );
	script_name( "TYPO3 Environment Variable Injection Vulnerability July16" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to an environment variable injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to PHP, when used as
  CGI, FPM or HHVM, exposes http headers also as environment variables starting
  with 'HTTP_'.TYPO3 is vulnerable through third party library guzzlehttp/guzzle
  which makes use of the environment variable 'HTTP_PROXY'." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to conduct MITM attacks on internal server subrequests
  or direct the server to initiate connections to arbitrary hosts." );
	script_tag( name: "affected", value: "TYPO3 versions 8.0.0 to 8.2.0" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 8.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-019" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://typo3.org/typo3-cms" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!typoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!typoVer = get_app_version( cpe: CPE, port: typoPort )){
	exit( 0 );
}
if(!IsMatchRegexp( typoVer, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(IsMatchRegexp( typoVer, "^8\\." )){
	if(version_in_range( version: typoVer, test_version: "8.0", test_version2: "8.2.0" )){
		report = report_fixed_ver( installed_version: typoVer, fixed_version: "8.2.1" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

