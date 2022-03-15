CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806664" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_cve_id( "CVE-2015-8760", "CVE-2015-8756" );
	script_bugtraq_id( 79210 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-01-19 11:49:38 +0530 (Tue, 19 Jan 2016)" );
	script_name( "TYPO3 Multiple Vulnerabilities-01 Jan16" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - An error in flashplayer which misses to validate flash and image files,

  - An error in encoding editor input." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to conduct Cross-Site Flashing attacks and Cross-Site
  Scripting attacks." );
	script_tag( name: "affected", value: "TYPO3 versions 6.2.0 to 6.2.15" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 6.2.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1034486" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1034485" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-015" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-014" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
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
if(IsMatchRegexp( typoVer, "^6\\.2" )){
	if(version_in_range( version: typoVer, test_version: "6.2.0", test_version2: "6.2.15" )){
		report = report_fixed_ver( installed_version: typoVer, fixed_version: "6.2.16" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

