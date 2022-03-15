CPE = "cpe:/a:ilohamail:ilohamail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16142" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 12252 );
	script_name( "IlohaMail Readable Configuration Files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Remote file access" );
	script_dependencies( "ilohamail_detect.sc" );
	script_mandatory_keys( "ilohamail/detected" );
	script_tag( name: "solution", value: "Upgrade to IlohaMail version 0.8.14-rc2 or later or
  reinstall following the 'Proper Installation' instructions in the INSTALL document." );
	script_tag( name: "summary", value: "The target is running at least one instance of IlohaMail that allows
  anyone to retrieve its configuration files over the web. These files may contain sensitive information.
  For example, conf/conf.inc may hold a username / password used for SMTP authentication." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
if(IsMatchRegexp( dir, "/source$" )){
	dir = ereg_replace( string: dir, pattern: "/source$", replace: "/conf" );
	for config in make_list( "conf.inc",
		 "mysqlrc.inc" ) {
		url = dir + "/" + config;
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(egrep( string: res, pattern: "<\\?php" ) && egrep( string: res, pattern: "\\$[A-Za-z_]+ *= *.+;" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

