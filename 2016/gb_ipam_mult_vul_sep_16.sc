CPE = "cpe:/a:phpipam:phpipam";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107047" );
	script_version( "$Revision: 12070 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 09:56:12 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-12 06:40:16 +0200 (Mon, 12 Sep 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "phpIPAM <= 1.2.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ipam_detect.sc" );
	script_mandatory_keys( "phpipam/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/138603/PHPIPAM-1.2.1-Cross-Site-Scripting-SQL-Injection.html" );
	script_xref( name: "URL", value: "https://phpipam.net/documents/changelog/" );
	script_tag( name: "summary", value: "phpIPAM is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "phpIPAM version 1.2.1 suffers from cross site scripting and remote SQL injection vulnerabilities." );
	script_tag( name: "impact", value: "Allows unauthorized disclosure of information, allows unauthorized modification and allows disruption of service." );
	script_tag( name: "affected", value: "phpIPAM 1.2.1 and earlier." );
	script_tag( name: "solution", value: "Update to phpIPAM 1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://phpipam.net" );
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
if(version_is_less_equal( version: vers, test_version: "1.2.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3 or later." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

