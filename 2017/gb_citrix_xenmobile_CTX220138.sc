CPE = "cpe:/a:citrix:xenmobile_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106887" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-06-20 15:46:37 +0700 (Tue, 20 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Citrix XenMobile Server XXE Processing Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_citrix_xenmobile_detect.sc" );
	script_mandatory_keys( "citrix_xenmobile_server/installed" );
	script_tag( name: "summary", value: "An XML External Entity (XXE) processing vulnerability has been identified
in Citrix XenMobile Server that could allow an unauthenticated attacker to retrieve potentially sensitive
information from the server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Citrix XenMobile Server 9.x and 10.x" );
	script_tag( name: "solution", value: "Update to version 10.5 Rolling Patch 3 or later." );
	script_xref( name: "URL", value: "https://support.citrix.com/article/CTX220138" );
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
if(version_is_less( version: version, test_version: "10.5.0.10038" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.5.0.10038" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

