if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100435" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)" );
	script_bugtraq_id( 37672 );
	script_cve_id( "CVE-2009-4486" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Novell iManager Importing/Exporting Schema Stack Buffer Overflow Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "novell_imanager_detect.sc" );
	script_mandatory_keys( "novellimanager/installed" );
	script_tag( name: "solution", value: "The vendor has released an advisory and fixes. Please see the
  references for details." );
	script_tag( name: "summary", value: "Novell iManager is prone to a stack-based buffer-overflow
  vulnerability because it fails to perform adequate boundary checks on user-supplied data." );
	script_tag( name: "impact", value: "Attackers may exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Novell iManager 2.7.2 and prior are vulnerable." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37672" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-001/" );
	script_xref( name: "URL", value: "http://www.novell.com/support/viewContent.do?externalId=7004985&sliceId=1" );
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
if(version_is_less_equal( version: version, test_version: "2.7.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

