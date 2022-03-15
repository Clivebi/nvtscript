CPE = "cpe:/a:apache:axis2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111007" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-03-20 08:00:00 +0100 (Fri, 20 Mar 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 40343 );
	script_name( "Apache Axis2 xsd Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_axis2_detect.sc", "sw_apache_axis2_services_detect.sc" );
	script_require_ports( "Services/www", 8080, 8081 );
	script_mandatory_keys( "axis2/installed", "axis2/services" );
	script_tag( name: "solution", value: "The vendor has released fixes. Please see the references for more
 information." );
	script_tag( name: "summary", value: "Apache Axis2 is prone to a directory-traversal vulnerability because
 it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to obtain sensitive
 information that could aid in further attacks." );
	script_tag( name: "affected", value: "Apache Axis2 1.4.1 is vulnerable. Other versions may be affected." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40343" );
	script_xref( name: "URL", value: "http://ws.apache.org/axis2/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12721/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
pattern = "<axisconfig name=\"AxisJava2.0\">";
for service in get_kb_list( "axis2/services" ) {
	url = dir + "/services/" + service + "?xsd=../conf/axis2.xml";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

