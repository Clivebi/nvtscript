CPE = "cpe:/a:invision_power_services:invision_power_board";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100882" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-11-01 13:16:04 +0100 (Mon, 01 Nov 2010)" );
	script_bugtraq_id( 44553 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Invision Power Board IP.Board Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44553" );
	script_xref( name: "URL", value: "http://www.invisionpower.com/" );
	script_xref( name: "URL", value: "http://community.invisionpower.com/topic/323970-ipboard-30x-31x-security-patch-released/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "invision_power_board_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "invision_power_board/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "IP.Board is prone to an information disclosure vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information that
  may aid in further attacks." );
	script_tag( name: "affected", value: "IP.Board 3.1.3 is vulnerable. Other versions may be affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
port = get_app_port( cpe: CPE );
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_in_range( version: vers, test_version: "3.1", test_version2: "3.1.3" ) || version_in_range( version: vers, test_version: "3.0", test_version2: "3.0.5" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

