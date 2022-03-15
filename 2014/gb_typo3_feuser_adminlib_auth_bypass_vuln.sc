CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804209" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2013-7080" );
	script_bugtraq_id( 64248 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-01-06 17:49:40 +0530 (Mon, 06 Jan 2014)" );
	script_name( "TYPO3 feuser_adminLib Authorization Bypass Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to modify backend
database tables." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in the 'feuser_adminLib.inc' file, which allows any links for
records created by this library to be manipulated to fill any field in the
configured database table with an arbitrary value." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.5.32, 4.7.17, 6.0.12 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone authorization bypass
vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version 4.5.0 to 4.5.31, 4.7.0 to 4.7.16 and 6.0.0 to 6.0.11" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56266/" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-004" );
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
	if(version_in_range( version: typoVer, test_version: "4.5.0", test_version2: "4.5.31" ) || version_in_range( version: typoVer, test_version: "4.7.0", test_version2: "4.7.16" ) || version_in_range( version: typoVer, test_version: "6.0.0", test_version2: "6.0.11" )){
		security_message( typoPort );
		exit( 0 );
	}
}

