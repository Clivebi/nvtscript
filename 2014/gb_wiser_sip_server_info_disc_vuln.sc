if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804454" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 67481 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-20 16:32:39 +0530 (Tue, 20 May 2014)" );
	script_name( "Wiser SIP Server Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Wiser SIP Server and is prone to information
disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to read
the backup information." );
	script_tag( name: "insight", value: "Wiser contains a flaw that allow a remote attacker to gain access to
backup information by sending a direct request for the
/voip/sipserver/class/baixarBackup.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain sensitive
information without prior authentication." );
	script_tag( name: "affected", value: "Wiser SIP Server version 2.10" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126700/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
sipPort = http_get_port( default: 80 );
sipReq = http_get( item: "/voip/sipserver/login/", port: sipPort );
sipRes = http_keepalive_send_recv( port: sipPort, data: sipReq, bodyonly: TRUE );
if(sipRes && ContainsString( sipRes, ">SIP Server<" )){
	sipReq = http_get( item: "/voip/sipserver/class/baixarBackup.php", port: sipPort );
	sipRes = http_send_recv( port: sipPort, data: sipReq, bodyonly: FALSE );
	if(ContainsString( sipRes, "radius.sql" ) && ContainsString( sipRes, "openser.sql" ) && ContainsString( sipRes, "Content-Description: File Transfer" )){
		security_message( port: sipPort );
		exit( 0 );
	}
}

