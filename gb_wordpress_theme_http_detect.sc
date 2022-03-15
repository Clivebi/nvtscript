if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112798" );
	script_version( "2020-11-23T08:54:59+0000" );
	script_tag( name: "last_modification", value: "2020-11-23 08:54:59 +0000 (Mon, 23 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-06 12:04:11 +0000 (Thu, 06 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WordPress Theme Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "Checks and reports which WordPress themes are installed on the target system." );
	script_xref( name: "URL", value: "https://wordpress.org/themes/" );
	script_timeout( 900 );
	exit( 0 );
}
CPE = "cpe:/a:wordpress:wordpress";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("cpe.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
themes = make_array( "activello/style.css", "colorlib Activello#---#Theme Name: Activello#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:activello#---#https://colorlib.com/wp/themes/activello", "affluent/style.css", "CPOThemes Affluent#---#Theme Name:Affluent#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:affluent#---#https://cpothemes.com/theme/affluent", "allegiant/style.css", "CPOThemes Allegiant#---#Theme Name:Allegiant#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:allegiant#---#https://cpothemes.com/theme/allegiant", "antreas/style.css", "MachoThemes Antreas#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:antreas", "bonkers/style.css", "colorlib Bonkers#---#Theme Name: Bonkers#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:bonkers#---#https://colorlib.com/wp/themes/bonkers", "brilliance/style.css", "CPOThemes Brilliance#---#Theme Name:Brilliance#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:brilliance#---#https://cpothemes.com/theme/brilliance", "clockstone/style.css", "CMSMasters Clockstone#---#Theme Name: Clockstone#---#Version: ([0-9.]+)#---#cpe:/a:cmsmasters:clockstone#---#http://clockstone.cmsmasters.net/", "designfolio/style.css", "PressCoders Designfolio#---#Theme Name: Designfolio#---#Version: ([0-9.]+)#---#cpe:/a:presscoders:designfolio", "DesignFolio-Plus/style.css", "UpThemes DesignFolio Plus#---#Theme Name: DesignFolio+#---#Version: ([0-9.]+)#---#cpe:/a:upthemes:designfolio-plus#---#https://github.com/UpThemes/DesignFolio-Plus", "Divi/style.css", "Elegant Themes Divi#---#Theme Name: Divi#---#Version: ([0-9.]+)#---#cpe:/a:elegantthemes:divi#---#https://www.elegantthemes.com/gallery/divi/", "Extra/style.css", "Elegant Themes Extra#---#Theme Name: Extra#---#Version: ([0-9.]+)#---#cpe:/a:elegantthemes:extra#---#https://www.elegantthemes.com/gallery/extra/", "flexolio/style.css", "Quarterpixel Flexolio#---#Theme Name: Flexolio#---#Version: ([0-9.]+)#---#cpe:/a:quarterpixel:flexolio", "illdy/style.css", "colorlib Illdy#---#Theme Name: Illdy#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:illdy#---#https://colorlib.com/wp/themes/illdy", "iloveit/style.css", "CosmoThemes I Love It#---#CosmoThemes#---#Version: ([0-9.]+)#---#cpe:/a:cosmothemes:iloveit#---#https://cosmothemes.com/i-love-it/", "medzone-lite/style.css", "MachoThemes MedZone Lite#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:medzone-lite#---#https://www.machothemes.com/medzone-lite/", "method/style.css", "Mysitemyway Method#---#Author: Mysitemyway#---#Version: ([0-9.]+)#---#cpe:/a:mysitemyway:method", "method/style.css", "BackStop Themes Method#---#Author: BackStop Themes#---#Version: ([0-9.]+)#---#cpe:/a:backstopthemes:method#---#https://backstopthemes.com", "naturemag-lite/style.css", "MachoThemes NatureMag-Lite#---#Author: Macho Themes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:naturemag-lite", "Newsmag/style.css", "MachoThemes Newsmag#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:newsmag#---#https://www.machothemes.com/newsmag-lite/", "newspaper-x/style.css", "colorlib Newspaper X#---#Theme Name: Newspaper X#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:newspaper-x#---#https://colorlib.com/wp/themes/newspaper-x", "mTheme-Unus/style.css", "mTheme-Unus#---#Theme Name: mTheme-Unus#---#Version: ([0-9.]+)#---#cpe:/a:fabrix:mtheme-unus#---#http://fabrix.net/", "photocrati-theme/style.css", "Photocrati Theme#---#Theme Name: Photocrati Theme#---#Version: ([0-9.]+)#---#cpe:/a:photocrati:photocrati-theme#---#http://www.photocrati.com/", "pixova-lite/style.css", "colorlib Pixova Lite#---#Theme Name: Pixova Lite#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:pixova-lite#---#https://colorlib.com/wp/themes/pixova-lite", "regina-lite/style.css", "MachoThemes Regina Lite#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:regina-lite#---#https://www.machothemes.com/regina-lite/", "shapely/style.css", "colorlib Shapely#---#Theme Name: Shapely#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:shapely#---#https://colorlib.com/wp/themes/shapely", "transcend/style.css", "CPOThemes Transcend#---#Theme Name:Transcend#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:transcend#---#https://cpothemes.com/theme/transcend" );
for style in keys( themes ) {
	infos = themes[style];
	if(!infos){
		continue;
	}
	infos = split( buffer: infos, sep: "#---#", keep: FALSE );
	if(!infos || max_index( infos ) < 4){
		continue;
	}
	name = infos[0];
	detect_regex = infos[1];
	vers_regex = infos[2];
	cpe = infos[3] + ":";
	theme_url = infos[4];
	extra = "";
	url = dir + "/wp-content/themes/" + style;
	res = http_get_cache( port: port, item: url );
	if(egrep( pattern: detect_regex, string: res, icase: TRUE ) && ContainsString( res, "Theme URI:" )){
		vers = eregmatch( pattern: vers_regex, string: res, icase: TRUE );
		if(!vers[1]){
			continue;
		}
		version = vers[1];
		kb_entry_name = ereg_replace( pattern: "/style.css", string: tolower( style ), replace: "", icase: TRUE );
		insloc = ereg_replace( pattern: "/style.css", string: url, replace: "", icase: TRUE );
		replace_kb_item( name: "wordpress/theme/detected", value: TRUE );
		set_kb_item( name: "wordpress/theme/" + kb_entry_name + "/detected", value: TRUE );
		if( theme_url ) {
			extra = "Theme Page: " + theme_url;
		}
		else {
			extra = "Theme Page: https://wordpress.org/themes/" + kb_entry_name + "/";
		}
		register_and_report_cpe( app: name, ver: version, concluded: vers[0], base: cpe, expr: "([0-9.]+)", insloc: insloc, regPort: port, regService: "www", conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ), extra: extra );
	}
}
exit( 0 );

