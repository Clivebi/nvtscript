if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800962" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3711" );
	script_name( "httpdx Web Server 'h_handlepeer()' Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36991" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2874" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/507042/100/0/threaded" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_httpdx_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "httpdx/installed" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to execute arbitrary code or crash
  the server via a specially crafted request." );
	script_tag( name: "affected", value: "httpdx Web Server version 1.4.3 and prior on windows." );
	script_tag( name: "insight", value: "A boundary error occurs in 'h_handlepeer()' in 'http.cpp' while processing
  overly long HTTP requests leading to a buffer overflow." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to httpdx Server version 1.4.4 or later." );
	script_tag( name: "summary", value: "The host is running httpdx Web Server and is prone to a Buffer
  Overflow vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
httpdxPort = http_get_port( default: 80 );
httpdxVer = get_kb_item( "httpdx/" + httpdxPort + "/Ver" );
if(!isnull( httpdxVer )){
	if(version_is_less( version: httpdxVer, test_version: "1.4.4" )){
		report = report_fixed_ver( installed_version: httpdxVer, fixed_version: "1.4.4" );
		security_message( port: httpdxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

