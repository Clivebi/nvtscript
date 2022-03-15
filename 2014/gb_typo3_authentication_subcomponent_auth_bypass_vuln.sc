CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804467" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-3945" );
	script_bugtraq_id( 67627 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-07-03 14:52:50 +0530 (Thu, 03 Jul 2014)" );
	script_name( "TYPO3 Authentication Subcomponent Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to authentication bypass
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is triggered as the program stores passwords for backend access as
MD5 hashes in the database." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to directly authenticate
to a backend users account without needing any knowledge of the password." );
	script_tag( name: "affected", value: "TYPO3 versions prior to 6.2" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 6.2 or later." );
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
	if(version_is_less( version: typoVer, test_version: "6.2" )){
		report = report_fixed_ver( installed_version: typoVer, fixed_version: "6.2" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}

