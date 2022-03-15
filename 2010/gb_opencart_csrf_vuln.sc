CPE = "cpe:/a:opencart:opencart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801227" );
	script_version( "$Revision: 13957 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 10:46:54 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)" );
	script_cve_id( "CVE-2010-1610" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "OpenCart Cross-Site Request Forgery Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "opencart_detect.sc" );
	script_mandatory_keys( "OpenCart/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform CSRF attacks,
  which will aid in further attacks." );
	script_tag( name: "affected", value: "OpenCart Version 1.4.7 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input in index.php,
  that allows remote attackers to hijack the authentication of an application
  administrator for requests that create an administrative account via a POST
  request with the route parameter set to 'user/user/insert'." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to OpenCart version 1.4.8 or later." );
	script_tag( name: "summary", value: "The host is running OpenCart and is prone to cross-site request
  forgery vulnerability." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/509313/100/0/threaded" );
	script_xref( name: "URL", value: "http://forum.opencart.com/viewtopic.php?f=16&t=10203&p=49654&hilit=csrf#p49654" );
	script_xref( name: "URL", value: "http://blog.visionsource.org/2010/01/28/opencart-csrf-vulnerability/" );
	script_xref( name: "URL", value: "http://www.opencart.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.4.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

