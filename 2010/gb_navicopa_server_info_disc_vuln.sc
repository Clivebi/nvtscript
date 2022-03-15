if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800411" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4529" );
	script_name( "NaviCOPA Web Server Source Code Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37014" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53799" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2927" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.org/0910-exploits/navicopa-disclose.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_navicopa_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "navicopa/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to display the source code
  of arbitrary files (e.g. PHP) instead of an expected HTML response." );
	script_tag( name: "affected", value: "NaviCOPA Web Server version 3.0.1.2 and prior on windows." );
	script_tag( name: "insight", value: "This issue is caused by an error when handling requests with the '%20' string
  appended to the file extension." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the NaviCOPA Web Server version 3.0.1.3 or later." );
	script_tag( name: "summary", value: "The host is running NaviCOPA Web Server and is prone to Source Code
  Disclosure vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
ncpaPort = http_get_port( default: 80 );
ncpaVer = get_kb_item( "NaviCOPA/" + ncpaPort + "/Ver" );
if(isnull( ncpaVer )){
	exit( 0 );
}
if(version_is_less_equal( version: ncpaVer, test_version: "3.01.2" )){
	report = report_fixed_ver( installed_version: ncpaVer, vulnerable_range: "Less than or equal to 3.01.2" );
	security_message( port: ncpaPort, data: report );
}

