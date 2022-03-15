CPE = "cpe:/a:hp:openview_network_node_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900211" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_bugtraq_id( 30984 );
	script_cve_id( "CVE-2008-3536", "CVE-2008-3537" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_name( "HP OpenView Network Node Manager Denial of Service Vulnerabilities" );
	script_dependencies( "secpod_hp_openview_nnm_detect.sc" );
	script_require_ports( "Services/www", 7510 );
	script_mandatory_keys( "HP/OVNNM/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31688/" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2485" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01537275" );
	script_tag( name: "summary", value: "This host is running HP OpenView Network Node Manager, which is
  prone to Denial of Service vulnerabilities." );
	script_tag( name: "insight", value: "Flaws are due to an error in ovalarmsrv program." );
	script_tag( name: "affected", value: "HP OpenView Network Node Manager (OV NNM) v7.01, v7.51, v7.53." );
	script_tag( name: "solution", value: "Apply the updates from the reverenced vendor advisory." );
	script_tag( name: "impact", value: "Successful exploitation can cause application to crash." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!vers = get_kb_item( "www/" + port + "/HP/OVNNM/Ver" )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "B.07.01" ) || version_is_equal( version: vers, test_version: "B.07.51" ) || version_is_equal( version: vers, test_version: "B.07.53" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

