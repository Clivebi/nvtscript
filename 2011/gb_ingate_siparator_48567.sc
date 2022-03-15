if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103209" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)" );
	script_bugtraq_id( 48567 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ingate SIParator SIP Module Remote Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48567" );
	script_xref( name: "URL", value: "http://www.ingate.com/Relnote.php?ver=492" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_ingate_siparator_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ingate_siparator/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Ingate SIParator is prone to a denial-of-service vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause SIP modules to reset,
  denying service to legitimate users." );
	exit( 0 );
}
require("version_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( port, "/Ingate_SIParator" ) )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.9.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

