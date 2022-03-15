if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107307" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-07 12:00:20 +0200 (Mon, 07 May 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_name( "Unprotected Web App Installers (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "sw_magento_detect.sc", "secpod_wordpress_detect_900182.sc", "osticket_detect.sc", "gb_dotnetnuke_detect.sc", "secpod_tikiwiki_detect.sc", "gb_nuxeo_platform_detect.sc", "gb_owncloud_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script attempts to identify installation pages of various
  Web Apps that are publicly accessible and not protected by account restrictions." );
	script_tag( name: "vuldetect", value: "Enumerate the remote web server and check if unprotected
  Web Apps are accessible for installation." );
	script_tag( name: "impact", value: "It is possible to install or reconfigure the software. In doing so,
  the attacker could overwrite existing configurations. It could be possible for the attacker to gain
  access to the base system" );
	script_tag( name: "solution", value: "Setup and/or installation pages for Web Apps should not be
  publicly accessible via a web server. Restrict access to it or remove it completely." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_timeout( 900 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
genericfiles = make_array( "/index.php", "Installer / Setup-Tool of multiple vendors#-#<title>((Microweber|phpipam) installation|Installation|WackoWiki Installation|(Piwik|Matomo) .* &rsaquo; Installation|LimeSurvey installer)</title>", "/index.php?module=Users&parent=Settings&view=SystemSetup", "VTiger CMS Installation tool.#-#<title>Install</title>", "/index.php/index/install", "Open Journal Systems installer#-#<title>O(JS|MP) Installation</title>", "/install.php", "Installer / Setup-Tool of multiple vendors#-#<title>((Moodle|PHP-Fusion) Install|Piwigo * - Installation|Monstra :: Install|Kohana Installation|SMF Installer|vtiger CRM .* - Configuration Wizard - Welcome)</title>", "/setup.php", "Installer / Setup-Tool of multiple versions of Zabbix#-#<title>Installation</title>|class=\"setup_wizard setup_wizard_welcome\"|Check of pre-requisites", "/admin/install", "Orchestra Platform installer#-#<title>Installer &mdash; Orchestra Platform</title>", "/admin#/mode", "NetIQ Web installer#-#<title>Installation</title>", "/cb_install/", "ClipBucket installer#-#<title>ClipBucket .* Installer</title>", "/centreon/install/setup.php", "Centreon monitoring tool installer#-#<title>Centreon Installation</title>", "/contao/install.php", "Contao OpenSource CMS installer#-#(GNU GENERAL PUBLIC LICENSE|enter a password to prevent)", "/contao/install", "Contao OpenSource CMS installer#-#GNU GENERAL PUBLIC LICENSE", "/farcry/core/webtop/install/index.cfm", "FarCry Core installer#-#<title>FarCry Core Installer</title>", "/Install", "Installer / Setup-Tool of multiple vendors#-#(<h1>Install concrete5</h1>|<title>(Group-Office|EspoCRM|nopCommerce) Installation|PrestaShop (Installation Assistant|Wizard Installer)|Subrion CMS Web Installer</title>|install SmartStore.NET now?|Nextpost Installation)", "/install/index.php", "AChecker or OpenCart installer#-#<title>(OpenCart - Installation|AChecker Installation|forma.lms installer)</title>", "/install/make-config.php", "ProjectSend installation tool#-#<title>Install &raquo; ProjectSend</title>", "/install/system-compatibility", "Acelle Mail installer#-#<title>Requirement - Acelle Installation</title>", "/installation/default.asp", "vp-asp shopping cart setup page#-#<title>Installation Wizard</title>", "/installation/index.php", "Joomla Web installer#-#<title>((Joomla! Web|JoomlaPack|Akeeba Backup|Mambo - Web) Installer)</title>", "/home/index.php", "XPress Engine CMS installer#-#<title>XE Installation</title>", "/module.php/core/frontpage_welcome.php", "simpleSAMLphp Installer.#-#<title>simpleSAMLphp installation page</title>", "/recovery/install/", "Shopware installer#-#<title>Shopware .* - Installer</title>", "/setup/index.php", "CubeCart / phpMyAdmin installer#-#<title>(CubeCart .* Installer|phpMyAdmin setup)</title>", "/setup/setup.php", "WaWision WaWi, ERP CRM installer#-#<title>WaWision Installer</title>", "/tao/install/", "TAO installer#-#<title>TAO Installation</title>", "/install/", "phpBB installer#-#<title>Introduction</title>#-#<span>Install</span></a></li>", "/v1/settings/first-login", "Rancher first login value is set to true#-#\"value\":\"true\"", "/v3/settings/first-login", "Rancher first login value is set to true#-#\"value\":\"true\"" );
rootdirfiles = make_array( "/login.htm", "D-Link Router Setup page#-#<title>Welcome to D-Link Router Setup</title>", "/adm/wizard.asp", "Intelbras NCLOUD Setup page#-#(<script>dw\\(MM_easywizard\\)</script>|\\.\\./nbox/first_page\\.png)#-#<title>Roteador NCLOUD" );
magentofiles = make_array( "/downloader/", "Magento installer#-#<title>Magento Installation Wizard</title>", "/index.php/install/", "Magento or XLRstats installer#-#<title>(Magento|XLRstats) Installation</title>" );
wordpressfiles = make_array( "/wp-admin/install.php", "WordPress installer#-#<title>WordPress &rsaquo; Installation</title>#-#=\"install\\.php\\?step=", "/wp-admin/setup-config.php", "WordPress installer#-#<title>WordPress &rsaquo; Setup Configuration File</title>" );
osticketfiles = make_array( "/setup/install.php", "osTicket installer#-#<title>osTicket Installer</title>" );
dotnetnukefiles = make_array( "/Install/InstallWizard.aspx", "DotNetNuke CMS installation tool#-#<title>        Installation</title>" );
tikiwikifiles = make_array( "/tiki-install.php", "Tiki wiki cms groupware installer#-#<title>Tiki Installer</title>" );
nuxeo_platformfiles = make_array( "/nuxeo/", "Nuxeo Platform installer#-#<title>Nuxeo Platform Installation wizard</title>" );
ocfiles = make_array( "/", "ownCloud installer#-#ownCloud.*</title>#-#(<legend>(Configure the database|Performance warning|Create an <strong>admin account</strong>)</legend>|value=\"Finish setup\" data-finishing=\"Finishing|placeholder=\"Database user\"|placeholder=\"Database password\")", "/index.php", "ownCloud installer#-#ownCloud.*</title>#-#(<legend>(Configure the database|Performance warning|Create an <strong>admin account</strong>)</legend>|value=\"Finish setup\" data-finishing=\"Finishing|placeholder=\"Database user\"|placeholder=\"Database password\")" );
var report, VULN;
func check_files( filesarray, dirlist, port ){
	var filesarray, dirlist, port, dir, file, infos, extra, url;
	for dir in dirlist {
		if(dir == "/"){
			dir = "";
		}
		for file in keys( filesarray ) {
			infos = split( buffer: filesarray[file], sep: "#-#", keep: FALSE );
			if(max_index( infos ) < 2){
				continue;
			}
			if( max_index( infos ) > 2 ) {
				extra = make_list( infos[2] );
			}
			else {
				extra = NULL;
			}
			url = dir + file;
			if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: infos[1], extra_check: extra, usecache: TRUE )){
				report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " - " + infos[0];
				VULN = TRUE;
			}
		}
	}
}
report = "The following Web App installers are unprotected and publicly accessible  (URL:Description): \n";
port = http_get_port( default: 80 );
dirlist = nasl_make_list_unique( "/", http_cgi_dirs( port: port ) );
check_files( filesarray: genericfiles, dirlist: dirlist, port: port );
check_files( filesarray: rootdirfiles, dirlist: make_list( "/" ), port: port );
madirs = get_app_location( port: port, cpe: "cpe:/a:magentocommerce:magento", nofork: TRUE );
if( madirs ) {
	magentodirlist = nasl_make_list_unique( madirs, dirlist );
}
else {
	magentodirlist = dirlist;
}
check_files( filesarray: magentofiles, dirlist: magentodirlist, port: port );
wpdirs = get_app_location( port: port, cpe: "cpe:/a:wordpress:wordpress", nofork: TRUE );
if( wpdirs ) {
	wordpressdirlist = nasl_make_list_unique( wpdirs, dirlist );
}
else {
	wordpressdirlist = dirlist;
}
check_files( filesarray: wordpressfiles, dirlist: wordpressdirlist, port: port );
osdirs = get_app_location( port: port, cpe: "cpe:/a:osticket:osticket", nofork: TRUE );
if( osdirs ) {
	osticketdirlist = nasl_make_list_unique( osdirs, dirlist );
}
else {
	osticketdirlist = dirlist;
}
check_files( filesarray: osticketfiles, dirlist: osticketdirlist, port: port );
dotnetdirs = get_app_location( port: port, cpe: "cpe:/a:dotnetnuke:dotnetnuke", nofork: TRUE );
if( dotnetdirs ) {
	dotnetnukedirlist = nasl_make_list_unique( dotnetdirs, dirlist );
}
else {
	dotnetnukedirlist = dirlist;
}
check_files( filesarray: dotnetnukefiles, dirlist: dotnetnukedirlist, port: port );
tikidirs = get_app_location( port: port, cpe: "cpe:/a:tiki:tikiwiki_cms/groupware", nofork: TRUE );
if( tikidirs ) {
	tikiwikidirlist = nasl_make_list_unique( tikidirs, dirlist );
}
else {
	tikiwikidirlist = dirlist;
}
check_files( filesarray: tikiwikifiles, dirlist: tikiwikidirlist, port: port );
nuxeodirs = get_app_location( port: port, cpe: "cpe:/a:nuxeo:platform", nofork: TRUE );
if( nuxeodirs ) {
	nuxeo_platformdirlist = nasl_make_list_unique( nuxeodirs, dirlist );
}
else {
	nuxeo_platformdirlist = dirlist;
}
check_files( filesarray: nuxeo_platformfiles, dirlist: nuxeo_platformdirlist, port: port );
ocdirs = get_app_location( port: port, cpe: "cpe:/a:owncloud:owncloud", nofork: TRUE );
if( ocdirs ) {
	ocdirlist = nasl_make_list_unique( ocdirs, dirlist );
}
else {
	ocdirlist = dirlist;
}
check_files( filesarray: ocfiles, dirlist: ocdirlist, port: port );
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

