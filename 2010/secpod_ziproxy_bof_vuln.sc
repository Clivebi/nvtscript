if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901128" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)" );
	script_cve_id( "CVE-2010-2350" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ziproxy PNG Image Processing Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40156" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59510" );
	script_xref( name: "URL", value: "http://ziproxy.cvs.sourceforge.net/viewvc/ziproxy/ziproxy-default/ChangeLog?revision=1.240&view=markup" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_ziproxy_server_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "Ziproxy/installed" );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to execute arbitrary code
  on the system with elevated privileges or cause the application to crash." );
	script_tag( name: "affected", value: "Ziproxy version 3.1.0." );
	script_tag( name: "insight", value: "The flaw is caused by a heap overflow error in the PNG decoder when processing
  malformed data, which could be exploited by attackers to crash an affected
  server or execute arbitrary code via a specially crafted PNG image." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest version of Ziproxy 3.1.1 or later." );
	script_tag( name: "summary", value: "The host is running Ziproxy server and is prone to buffer overflow
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
zipPort = http_get_port( default: 8080 );
ziproxyVer = get_kb_item( "www/" + zipPort + "/Ziproxy" );
if(!ziproxyVer){
	exit( 0 );
}
if(version_is_less_equal( version: ziproxyVer, test_version: "3.1.0" )){
	report = report_fixed_ver( installed_version: ziproxyVer, vulnerable_range: "Less or equal to 3.1.0" );
	security_message( port: zipPort, data: report );
}

