CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804220" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2010-5097", "CVE-2010-5098", "CVE-2010-5099", "CVE-2010-5100", "CVE-2010-5101", "CVE-2010-5102", "CVE-2010-5103", "CVE-2010-5104" );
	script_bugtraq_id( 45470 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-01-09 15:55:26 +0530 (Thu, 09 Jan 2014)" );
	script_name( "TYPO3 Multiple Vulnerabilities Dec10" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to get sensitive
information or execute SQL commands." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist in the application:

  - An error exists in fileDenyPattern functionality, which does not properly
filter file types.

  - An error exists enlarge functionality, FORM content object, list module and
class.em_unzip.php script, which fails to validate certain user provided
input properly.

  - An error exists in escapeStrForLike method, which does not properly escape
input when the MySQL database is set to sql_mode NO_BACKSLASH_ESCAPES." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.2.16, 4.3.9, 4.4.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "TYPO3 version 4.2.x before 4.2.16, 4.3.x before 4.3.9, and 4.4.x before 4.4.5" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35770" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-022/" );
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
	if(version_in_range( version: typoVer, test_version: "4.2.0", test_version2: "4.2.15" ) || version_in_range( version: typoVer, test_version: "4.3.0", test_version2: "4.3.8" ) || version_in_range( version: typoVer, test_version: "4.4.0", test_version2: "4.4.4" )){
		security_message( typoPort );
		exit( 0 );
	}
}

