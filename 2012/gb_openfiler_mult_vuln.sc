if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802967" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 55500 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-09-25 17:31:13 +0530 (Tue, 25 Sep 2012)" );
	script_name( "Openfiler Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42507" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/21191/" );
	script_xref( name: "URL", value: "http://forums.cnet.com/7726-6132_102-5357559.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/116405/openfiler_networkcard_exec.rb.txt" );
	script_xref( name: "URL", value: "http://itsecuritysolutions.org/2012-09-06-Openfiler-v2.x-multiple-vulnerabilities/" );
	script_xref( name: "URL", value: "https://dev.openfiler.com/attachments/152/Openfiler_v2.99.1_multiple_vulnerabilities.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 446 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code, arbitrary commands in a user's browser session in context
  of an affected site and gain sensitive information." );
	script_tag( name: "affected", value: "Openfiler versions 2.3, 2.99.1, 2.99.2." );
	script_tag( name: "insight", value: "- 'usercookie' and 'passcookie' cookies contain the username and
  password, respectively, in plain text and these cookies are not protected with
  the 'HttpOnly' flag.

  - Input passed to the 'device' parameter in system.html and 'targetName'
    parameter in volumes_iscsi_targets.html is not properly sanitised before
    being returned to the user.

  - Access not being restricted to uptime.html and phpinfo.html can be
    exploited to disclose PHP configuration details.

  - Input passed to the 'device' parameter in
    /opt/openfiler/var/www/htdocs/admin/system.html is not properly
    satinitised, which allows 'openfiler' user to execute arbitrary commands
    by injecting commands into the 'device' parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Openfiler and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 446 );
res = http_get_cache( item: "/", port: port );
if(res && ContainsString( res, ">Openfiler Storage Control Center<" ) && ContainsString( res, ">Openfiler<" )){
	req2 = http_get( item: "/phpinfo.html", port: port );
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(res2 && ContainsString( res2, ">phpinfo()<" ) && ContainsString( res2, ">System" ) && ContainsString( res2, ">PHP API" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

