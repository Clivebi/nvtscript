CPE = "cpe:/h:sierra_wireless:acemanager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106077" );
	script_version( "$Revision: 13659 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-17 11:21:09 +0700 (Tue, 17 May 2016)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_name( "Sierra Wireless AceManager Default Password" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sierrawireless_acemanager_detect.sc" );
	script_mandatory_keys( "sierra_wireless_acemanager/installed" );
	script_tag( name: "summary", value: "Default password for AceManager was found." );
	script_tag( name: "vuldetect", value: "Tries to log in with the default users 'user' and 'viewer'." );
	script_tag( name: "affected", value: "Sierra Wireless devices with AceManager installed." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
users = make_list( "user",
	 "viewer" );
found_users = "";
for user in users {
	data = "<request xmlns=\"urn:acemanager\">\r\n" + "<connect>\r\n" + "<login>" + user + "</login>\r\n" + "<password><![CDATA[12345]]></password>\r\n" + "</connect>\r\n" + "</request>";
	len = strlen( data );
	req = "POST /xml/Connect.xml HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Content-Type: text/xml\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "status='0' message='OK'" )){
		if( found_users == "" ) {
			found_users = user;
		}
		else {
			found_user += ", " + user;
		}
	}
}
if(found_users != ""){
	report = NASLString( "It was possible to log in with the user(s) '", found_users, "' and the default password '12345'" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

