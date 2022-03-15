CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804204" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2013-4250" );
	script_bugtraq_id( 61797 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-01-06 11:28:27 +0530 (Mon, 06 Jan 2014)" );
	script_name( "TYPO3 File Abstraction Code Execution Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
commands." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in file upload component and the File Abstraction Layer, which
allows to upload PHP files with arbitrary code." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 6.0.8, 6.1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to code execution
vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version 6.0.0 to 6.0.7, 6.1.0 to 6.1.2" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53529/" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-002" );
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
	if(version_in_range( version: typoVer, test_version: "6.0.0", test_version2: "6.0.7" ) || version_in_range( version: typoVer, test_version: "6.1.0", test_version2: "6.1.2" )){
		security_message( typoPort );
		exit( 0 );
	}
}

