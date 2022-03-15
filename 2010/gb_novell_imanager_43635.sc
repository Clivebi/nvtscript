if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100835" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)" );
	script_bugtraq_id( 43635 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_name( "Novell iManager 'getMultiPartParameters()' Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43635" );
	script_xref( name: "URL", value: "http://www.novell.com/products/consoles/imanager/features.html" );
	script_xref( name: "URL", value: "http://www.novell.com/support/viewContent.do?externalId=7006515" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-190/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "novell_imanager_detect.sc" );
	script_mandatory_keys( "novellimanager/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Novell iManager is prone to an arbitrary-file-upload vulnerability because
  it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to upload arbitrary files to the affected
  computer. This can result in arbitrary code execution within the context of the vulnerable application." );
	script_tag( name: "affected", value: "Novell iManager 2.7.3.2 and prior are vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:novell:imanager",
	 "cpe:/a:netiq:imanager" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!version = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.7.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

