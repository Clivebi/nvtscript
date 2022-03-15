CPE = "cpe:/a:horde:horde_groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11617" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "Horde and IMP test disclosure" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 Sverre H. Huseby" );
	script_family( "Web application abuses" );
	script_dependencies( "horde_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "horde/installed" );
	script_tag( name: "solution", value: "test.php and imp/test.php should be deleted, or they should be made
  unreadable by the web server." );
	script_tag( name: "summary", value: "The remote server is running Horde and/or IMP with test scripts available
  from the outside. The scripts may leak server-side information that is valuable to an attacker." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = make_list( "/test.php",
	 "/test.php3",
	 "/imp/test.php",
	 "/imp/test.php3" );
for f in files {
	url = dir + f;
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res == NULL){
		exit( 0 );
	}
	if(ContainsString( res, "PHP Version" ) && ( ContainsString( res, "Horde Version" ) || ContainsString( res, "IMP Version" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

