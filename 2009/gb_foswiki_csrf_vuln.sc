CPE = "cpe:/a:foswiki:foswiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800613" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1434" );
	script_name( "Foswiki Cross-Site Request Forgery Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foswiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Foswiki/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34863" );
	script_xref( name: "URL", value: "http://foswiki.org/Support/SecurityAlert-CVE-2009-1434" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack." );
	script_tag( name: "affected", value: "Foswiki version prior to 1.0.5." );
	script_tag( name: "insight", value: "An application allowing users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests." );
	script_tag( name: "solution", value: "Upgrade to version 1.0.5 or later." );
	script_tag( name: "summary", value: "The host is running Foswiki and is prone to Cross-Site Request Forgery
  Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

