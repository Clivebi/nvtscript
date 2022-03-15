CPE = "cpe:/o:cyberoam:cyberoam_os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106865" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-06-12 16:35:53 +0700 (Mon, 12 Jun 2017)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Sophos Cyberoam UMT/NGFW XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_cyberoam_umt_ngfw_detect.sc" );
	script_mandatory_keys( "cyberoam_umt_ngfw/detected" );
	script_tag( name: "summary", value: "Sophos Cyberoam UMT/NGFW is prone to a cross-site scripting vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists within the handling of request to 'LiveConnectionDetail.jsp'
application. GET parameters 'applicationname' and 'username' are not improperly sanitized allowing an attacker to
inject arbitrary javascript into the page." );
	script_tag( name: "affected", value: "Sophos Cyberoam UMT/NGFW 10.6.4 and prior" );
	script_tag( name: "solution", value: "Update to version 10.6.5 or later." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2017/Jun/4" );
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
if(version_is_less( version: version, test_version: "10.6.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.6.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

