CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804465" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-3944", "CVE-2014-3946" );
	script_bugtraq_id( 67629, 67624 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-07-03 13:22:50 +0530 (Thu, 03 Jul 2014)" );
	script_name( "TYPO3 Multiple Vulnerabilities-02 July-2104" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to:

  - An error in the authentication subcomponent that is triggered as the program
  fails to invalidate user's sessions that have timed out.

  - The program fails to honor user groups of logged in users when caching
  queries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to easily gain access
to a users session and gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "TYPO3 versions 6.2.0 to 6.2.2" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 6.2.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58901" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-001" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(typoVer = get_app_version( cpe: CPE, port: typoPort )){
	if(!IsMatchRegexp( typoVer, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
		exit( 0 );
	}
	if(version_in_range( version: typoVer, test_version: "6.2.0", test_version2: "6.2.2" )){
		report = report_fixed_ver( installed_version: typoVer, vulnerable_range: "6.2.0 - 6.2.2" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}

