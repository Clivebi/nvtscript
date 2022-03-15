CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803991" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2009-3634" );
	script_bugtraq_id( 36801 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-12-30 14:55:43 +0530 (Mon, 30 Dec 2013)" );
	script_name( "TYPO3 felogin Cross Site Scripting Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in the front-end login box (felogin), which fails to validate
certain user inputs" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.2.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to cross site scripting
vulnerability." );
	script_tag( name: "affected", value: "TYPO3 versions 4.2.0 to 4.2.6" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53926" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37122" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2009-016/" );
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
	if(version_in_range( version: typoVer, test_version: "4.2.0", test_version2: "4.2.6" )){
		report = report_fixed_ver( installed_version: typoVer, vulnerable_range: "4.2.0 - 4.2.6" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}

