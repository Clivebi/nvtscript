CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803985" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2008-2717", "CVE-2008-2718" );
	script_bugtraq_id( 29657 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-24 16:42:36 +0530 (Tue, 24 Dec 2013)" );
	script_name( "TYPO3 File Upload Cross Site Scripting Vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code and script code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist in the application:

  - Insufficiently restrictive default fileDenyPattern for Apache which allows
  bypass security restrictions and upload configuration files such as
  .htaccess, or conduct file upload attacks using multiple extensions.

  - An error in fe_adminlib.inc which is not properly sanitised before being
  returned to the user" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.0.9 or 4.1.7 or 4.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to file upload and cross site
  scripting vulnerabilities." );
	script_tag( name: "affected", value: "TYPO3 versions before 4.0.9, 4.1.0 to 4.1.7 and 4.2.0" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30619" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/42988" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/TYPO3-20080611-1" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc", "httpver.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!typoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
banner = http_get_remote_headers( port: typoPort );
if(!banner && !ContainsString( banner, "Apache" )){
	exit( 0 );
}
if(typoVer = get_app_version( cpe: CPE, port: typoPort )){
	if(!IsMatchRegexp( typoVer, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
		exit( 0 );
	}
	if(version_is_less( version: typoVer, test_version: "4.0.9" ) || version_in_range( version: typoVer, test_version: "4.1.0", test_version2: "4.1.7" ) || version_is_equal( version: typoVer, test_version: "4.2.0" )){
		security_message( port: typoPort );
		exit( 0 );
	}
}
exit( 99 );

