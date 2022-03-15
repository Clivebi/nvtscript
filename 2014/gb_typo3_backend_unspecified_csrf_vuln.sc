CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804222" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_bugtraq_id( 46377 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-01-10 12:10:05 +0530 (Fri, 10 Jan 2014)" );
	script_name( "TYPO3 Backend Unspecified CSRF Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to perform cross-site
  scripting attacks, Web cache poisoning, and other malicious activities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in typo3 backend, which is caused by improper validation of
  user supplied input." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to cross site request forgery
  vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version 4.2.x to 4.2.16, 4.3.x to 4.3.9, and 4.4.x to 4.4.5" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65387" );
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
	if(version_in_range( version: typoVer, test_version: "4.2.0", test_version2: "4.2.16" ) || version_in_range( version: typoVer, test_version: "4.3.0", test_version2: "4.3.9" ) || version_in_range( version: typoVer, test_version: "4.4.0", test_version2: "4.4.5" )){
		security_message( typoPort );
		exit( 0 );
	}
}

