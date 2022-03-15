CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808271" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-07-27 10:28:48 +0530 (Wed, 27 Jul 2016)" );
	script_name( "TYPO3 Frontend Login SQL Injection Vulnerability July16" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to an sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper escaping
  of user supplied input by frontend login component." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to execute arbitrary sql commands." );
	script_tag( name: "affected", value: "TYPO3 versions 6.2.0 to 6.2.25,
  7.6.0 to 7.6.9" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 6.2.26 or
  7.6.10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2016-016/" );
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
if( IsMatchRegexp( typoVer, "^6\\.2" ) ){
	if(version_in_range( version: typoVer, test_version: "6.2.0", test_version2: "6.2.25" )){
		fix = "6.2.26";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( typoVer, "^7\\.6" )){
		if(version_in_range( version: typoVer, test_version: "7.6.0", test_version2: "7.6.9" )){
			fix = "7.6.10";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: typoVer, fixed_version: fix );
	security_message( port: typoPort, data: report );
	exit( 0 );
}
exit( 99 );

