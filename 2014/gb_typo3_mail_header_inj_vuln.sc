CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803983" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2007-1081" );
	script_bugtraq_id( 22668 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-12-23 18:23:18 +0530 (Mon, 23 Dec 2013)" );
	script_name( "TYPO3 Mail Header Injection Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject arbitrary
email headers." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in class.t3lib_formmail.php script which fails to properly
validate certain email headers." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.0.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to mail header injection
vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version before 4.0.5" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/24207" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/32630" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20070221-1/" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(version_is_less( version: typoVer, test_version: "4.0.5" )){
		report = report_fixed_ver( installed_version: typoVer, fixed_version: "4.0.5" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}

