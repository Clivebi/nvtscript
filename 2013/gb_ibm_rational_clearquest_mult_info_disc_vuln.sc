if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803709" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 54222 );
	script_cve_id( "CVE-2012-0744" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-03 17:40:28 +0530 (Mon, 03 Jun 2013)" );
	script_name( "IBM Rational ClearQuest Multiple Information Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74671" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21606317" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21599361" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information." );
	script_tag( name: "affected", value: "IBM Rational ClearQuest 7.1.x to 7.1.2.7 and 8.x to 8.0.0.3" );
	script_tag( name: "insight", value: "The flaws are due to improper access controls on certain post-installation
  sample scripts. By sending a direct request, an attacker could obtain system
  paths, product versions, and other sensitive information." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with IBM Rational ClearQuest and is prone to
  multiple information disclosure vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
sndReq = http_get( item: "/cqweb/login", port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: TRUE );
if(ContainsString( rcvRes, ">Rational<" ) && ContainsString( rcvRes, "Welcome to Rational ClearQuest Web" )){
	sndReq = http_get( item: "/cqweb/j_security_check", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(( IsMatchRegexp( rcvRes, "HTTP/1.. 200 OK" ) ) && ( !IsMatchRegexp( rcvRes, "HTTP/1.. 404" ) ) && ( !ContainsString( rcvRes, ">Object not found!<" ) )){
		security_message( port );
		exit( 0 );
	}
}

