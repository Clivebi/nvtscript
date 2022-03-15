CPE = "cpe:/a:pidgin:pidgin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800824" );
	script_version( "2020-11-12T09:50:32+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1889" );
	script_bugtraq_id( 35530 );
	script_name( "Pidgin OSCAR Protocol Denial Of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_lin.sc" );
	script_mandatory_keys( "Pidgin/Lin/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35652" );
	script_xref( name: "URL", value: "http://developer.pidgin.im/ticket/9483" );
	script_xref( name: "URL", value: "http://pidgin.im/pipermail/devel/2009-May/008227.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause an application crash." );
	script_tag( name: "affected", value: "Pidgin version prior to 2.5.8 on Linux" );
	script_tag( name: "insight", value: "Error in OSCAR protocol implementation leads to the application misinterpreting
  the ICQWebMessage message type as ICQSMS message type via a crafted ICQ web
  message that triggers allocation of a large amount of memory." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.5.8." );
	script_tag( name: "summary", value: "This host has installed Pidgin and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "2.5.8" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.5.8" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

