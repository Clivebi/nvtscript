if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800541" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-0769" );
	script_bugtraq_id( 33609 );
	script_name( "Qip ICQ Message Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33851" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/500656/100/0/threaded" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_qip_detect.sc" );
	script_mandatory_keys( "QIP/Version" );
	script_tag( name: "impact", value: "Attackers may exploit this issue to crash the application." );
	script_tag( name: "affected", value: "QIP version 2005 build 8082 and prior on Windows" );
	script_tag( name: "insight", value: "Issue generated due to an error in handling Rich Text Format ICQ messages." );
	script_tag( name: "solution", value: "Upgrade to latest version." );
	script_tag( name: "summary", value: "This host is installed with QIP and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
qipVer = get_kb_item( "QIP/Version" );
if(!qipVer){
	exit( 0 );
}
if(version_is_less_equal( version: qipVer, test_version: "8.0.8.2" )){
	report = report_fixed_ver( installed_version: qipVer, vulnerable_range: "Less than or equal to 8.0.8.2" );
	security_message( port: 0, data: report );
}

