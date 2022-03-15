if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804413" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-6037" );
	script_bugtraq_id( 66024 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-03-17 13:12:47 +0530 (Mon, 17 Mar 2014)" );
	script_name( "Aker Secure Mail Gateway Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running Aker Secure Mail Gateway and is prone to cross-site
  scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'msg_id' GET parameter to webgui/cf/index.php is not
  properly sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Aker Secure Mail Gateway version 2.5.2 and prior." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57236" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/687278" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125599" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Mar/51" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
akerPort = http_get_port( default: 80 );
if(!http_can_host_php( port: akerPort )){
	exit( 0 );
}
akerReq = http_get( item: "/login", port: akerPort );
akerRes = http_keepalive_send_recv( port: akerPort, data: akerReq );
if(ContainsString( akerRes, ">Aker Secure Mail Gateway<" ) && ContainsString( akerRes, "Aker Security Solutions<" )){
	url = "/webgui/cf/index.php?msg_id=><" + "script>alert(document.cookie);</script>";
	if(http_vuln_check( port: akerPort, url: url, check_header: TRUE, pattern: "><script>alert\\(document.cookie\\);</script>", extra_check: ">Aker Secure Mail Gatewa" )){
		report = http_report_vuln_url( port: akerPort, url: url );
		security_message( port: akerPort, data: report );
		exit( 0 );
	}
}

