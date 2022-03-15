CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805981" );
	script_version( "$Revision: 11975 $" );
	script_cve_id( "CVE-2015-5956" );
	script_bugtraq_id( 76692 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-08 10:03:49 +0530 (Thu, 08 Oct 2015)" );
	script_name( "TYPO3 'sanitizeLocalUrl' function Cross-Site Scripting Vulnerability (SA-2015-009)" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the user input passed
  via 'returnUrl' and 'redirect_url' parameters to sanitizeLocalUrl function is
  not validated before returning to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote authenticated attackers to execute arbitrary HTML and script code in
  a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "TYPO3 versions 6.2.x prior to 6.2.15,
  and 7.0.x prior to 7.4.0" );
	script_tag( name: "solution", value: "Update to TYPO3 version 6.2.15 or 7.4.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/536464/100/0/threaded" );
	script_xref( name: "URL", value: "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-009" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_in_range( version: typoVer, test_version: "6.2.0", test_version2: "6.2.14" )){
	fix = "6.2.15";
	VULN = TRUE;
}
if(version_in_range( version: typoVer, test_version: "7.0.0", test_version2: "7.3.0" )){
	fix = "7.4.0";
	VULN = TRUE;
}
if(VULN){
	report = report_fixed_ver( installed_version: typoVer, fixed_version: fix );
	security_message( port: typoPort, data: report );
	exit( 0 );
}
exit( 99 );

