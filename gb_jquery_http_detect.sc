if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141622" );
	script_version( "2021-09-21T07:58:23+0000" );
	script_tag( name: "last_modification", value: "2021-09-21 07:58:23 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-11-01 09:53:59 +0700 (Thu, 01 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "jQuery Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_add_preference( name: "Follow redirects", type: "checkbox", value: "no", id: 1 );
	script_tag( name: "summary", value: "HTTP based detection of jQuery." );
	script_tag( name: "insight", value: "Script preference 'Follow redirects':

  This script currently isn't following HTTP redirects (30x) by default. If you would like to enable
  this functionality, please set the related preference to 'yes'.

  Please do note that this functionality currently might cause a reporting of the same jQuery
  installation / location multiple times for specific / special targets. If this is the case for the
  target in question, please disable it again for the time being." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
func extract_jquery_location( jquerydir, jqueryfile, basedir ){
	var jquerydir, jqueryfile, basedir;
	var ret_array, location, fullurl;
	ret_array = make_array();
	if( !isnull( jquerydir ) ){
		if( !IsMatchRegexp( jquerydir, "^/" ) && !IsMatchRegexp( jquerydir, "^\\./" ) ) {
			location = basedir + "/" + jquerydir;
		}
		else {
			if( IsMatchRegexp( jquerydir, "^\\./" ) ) {
				location = ereg_replace( string: jquerydir, pattern: "^(\\./)", replace: basedir + "/" );
			}
			else {
				if( IsMatchRegexp( jquerydir, "^/" ) ) {
					location = jquerydir;
				}
				else {
					location = basedir + jquerydir;
				}
			}
		}
	}
	else {
		if( !IsMatchRegexp( jquerydir, "^/" ) && !IsMatchRegexp( jquerydir, "^\\./" ) ) {
			location = basedir;
		}
		else {
			if( IsMatchRegexp( jquerydir, "^\\./" ) ) {
				location = ereg_replace( string: jquerydir, pattern: "^(\\./)", replace: basedir + "/" );
			}
			else {
				location = basedir;
			}
		}
	}
	if(location != "/"){
		location = ereg_replace( string: location, pattern: "(/)$", replace: "" );
	}
	if(!IsMatchRegexp( jqueryfile, "^/" )){
		jqueryfile = "/" + jqueryfile;
	}
	ret_array["location"] = location;
	if( location == "/" ) {
		ret_array["fullurl"] = jqueryfile;
	}
	else {
		ret_array["fullurl"] = location + jqueryfile;
	}
	return ret_array;
}
pattern = "src=[\"\']([^ ]*)(jquery[-.]?([0-9.]+(-rc[0-9])?)?(\\.min|\\.slim|\\.slim\\.min)?\\.js)";
detected_urls = make_list();
detected_vers = make_list();
port = http_get_port( default: 80 );
opt = script_get_preference( name: "Follow redirects", id: 1 );
if(opt && opt == "yes"){
	follow_redirects = TRUE;
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/" );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] " )){
		continue;
	}
	if(follow_redirects && IsMatchRegexp( res, "^HTTP/1\\.[01] 30[0-9]" ) && location = http_extract_location_from_redirect( port: port, data: res, current_dir: install )){
		res = http_get_cache( port: port, item: location );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] " )){
			continue;
		}
		install = http_extract_location_from_redirect( port: port, data: res, dir_only: TRUE, current_dir: install );
	}
	detect = eregmatch( pattern: pattern, string: res );
	if(!detect){
		continue;
	}
	version = "unknown";
	extra = "";
	if( !isnull( detect[3] ) ){
		infos = extract_jquery_location( jquerydir: detect[1], jqueryfile: detect[2], basedir: dir );
		location = infos["location"];
		if(!location){
			location = "unknown";
		}
		if(in_array( search: location, array: detected_urls, part_match: FALSE )){
			continue;
		}
		vers = eregmatch( pattern: "([0-9.]+(-rc[0-9])?)", string: detect[3] );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		detected_urls = make_list( detected_urls,
			 location );
		set_kb_item( name: "jquery/detected", value: TRUE );
		set_kb_item( name: "jquery/http/detected", value: TRUE );
		set_kb_item( name: "jquery/http/" + port + "/installs", value: port + "#---#" + location + "#---#" + version + "#---#" + detect[0] );
	}
	else {
		if(!isnull( detect[2] )){
			infos = extract_jquery_location( jquerydir: detect[1], jqueryfile: detect[2], basedir: dir );
			location = infos["location"];
			url = infos["fullurl"];
			if(!location){
				location = "unknown";
			}
			if( !IsMatchRegexp( detect[1], "^https?://" ) && !IsMatchRegexp( detect[1], "^//" ) ){
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				req = http_get( port: port, item: url );
				res = http_keepalive_send_recv( port: port, data: req );
				if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
					vers = eregmatch( pattern: "jQuery (JavaScript Library )?v([0-9.]+(-rc[0-9])?)", string: res, icase: FALSE );
					if(!isnull( vers[2] )){
						version = vers[2];
						concl = vers[0];
					}
					if(version == "unknown" && ContainsString( res, "jQuery requires a window with a document" )){
						vers = eregmatch( pattern: "version\\s*=\\s*[\"\']?([0-9.]+(-rc[0-9])?)", string: res, icase: FALSE );
						if(!isnull( vers[1] )){
							version = vers[1];
							concl = vers[0];
						}
					}
				}
			}
			else {
				extra = "The jQuery library is hosted on a different server. Because of this it is not possible to gather the ";
				extra += "version by a direct file access. Please manually inspect the version which gets included on this web page.";
				location = "Externally hosted";
				concl = detect[0] + " embedded into URL " + install;
			}
			if(in_array( search: location, array: detected_urls, part_match: FALSE )){
				continue;
			}
			detected_urls = make_list( detected_urls,
				 location );
			if(ContainsString( location, "../" )){
				if(in_array( search: version, array: detected_vers, part_match: FALSE )){
					continue;
				}
				detected_vers = make_list( detected_vers,
					 version );
			}
			set_kb_item( name: "jquery/detected", value: TRUE );
			set_kb_item( name: "jquery/http/detected", value: TRUE );
			set_kb_item( name: "jquery/http/" + port + "/installs", value: port + "#---#" + location + "#---#" + version + "#---#" + concl + "#---#" + concUrl + "#---#" + extra );
		}
	}
}
exit( 0 );

