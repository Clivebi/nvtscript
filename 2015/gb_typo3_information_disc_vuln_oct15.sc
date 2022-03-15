CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806601" );
	script_version( "$Revision: 11452 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-20 14:56:05 +0530 (Tue, 20 Oct 2015)" );
	script_name( "TYPO3 Information Disclosure Vulnerability - Oct15" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as no authentication is
  required to access certain pages for specific URLs." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to gain access to sensitive information." );
	script_tag( name: "affected", value: "TYPO3 versions 4.2 and 4.5" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133961" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(!IsMatchRegexp( typoVer, "[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(IsMatchRegexp( typoVer, "(4\\.(2|5))" )){
	report = report_fixed_ver( installed_version: typoVer, fixed_version: "None Available" );
	security_message( port: typoPort, data: report );
	exit( 0 );
}
exit( 99 );

