CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900421" );
	script_version( "2021-09-01T13:34:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 13:34:42 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252" );
	script_bugtraq_id( 32844 );
	script_name( "MediaWiki Multiple Vulnerabilities Dec08" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33133" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary codes in
  the context of the web application and execute cross site scripting attacks." );
	script_tag( name: "affected", value: "MediaWiki version 1.13.0 to 1.13.2

  MediaWiki version 1.12.x to 1.12.1

  MediaWiki versions prior to 1.6.11." );
	script_tag( name: "insight", value: "The flaws are due to:

  - input is not properly sanitised before being returned to the user

  - input related to uploads is not properly sanitised before being used

  - SVG scripts are not properly sanitised before being used

  - the application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests." );
	script_tag( name: "solution", value: "Upgrade to the latest versions 1.13.3, 1.12.2 or 1.6.11." );
	script_tag( name: "summary", value: "This host is running MediaWiki and is prone to Multiple
  Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.13.0", test_version2: "1.13.2" ) || version_in_range( version: vers, test_version: "1.12.0", test_version2: "1.12.1" ) || version_is_less_equal( version: vers, test_version: "1.6.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.13.3, 1.12.2 or 1.6.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

