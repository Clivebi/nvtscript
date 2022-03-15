if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111107" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-07-02 13:00:00 +0200 (Sat, 02 Jul 2016)" );
	script_name( "ownCloud/Nextcloud Unprotected Data Directory" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc", "gb_nextcloud_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "owncloud_or_nextcloud/installed" );
	script_xref( name: "URL", value: "https://doc.owncloud.org/server/latest/admin_manual/configuration_server/harden_server.html#place-data-directory-outside-of-the-web-root" );
	script_tag( name: "summary", value: "The host is installed with ownCloud/Nextcloud and
  is exposing an unprotected data directory." );
	script_tag( name: "vuldetect", value: "Try to access common existing files to
  check if the protection of the data directory is not working." );
	script_tag( name: "insight", value: "The flaw exists due to a missing protection
  of the data directory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated attacker to enumerate existing user files within the
  data directory and gain access to sensitive data stored within it." );
	script_tag( name: "affected", value: "All ownCloud/Nextcloud versions." );
	script_tag( name: "solution", value: "Protect the ownCloud/Nextcloud data directory via
  .htaccess or move the data directory out of the webservers web root. See the reference
  for more info." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:owncloud:owncloud",
	 "cpe:/a:nextcloud:nextcloud" );
files = make_array( "/data/htaccesstest.txt", "This is used for testing whether htaccess", "/data/owncloud.log", "(\"app\":\"|\"reqId\":\")", "/data/nextcloud.log", "(\"app\":\"|\"reqId\":\")", "/data/owncloud.db", "SQLite format" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!dir = get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
vuln = FALSE;
report = "The following files could be accessed:\n";
if(dir == "/"){
	dir = "";
}
for file in keys( files ) {
	url = dir + file;
	if(http_vuln_check( port: port, url: url, pattern: files[file], check_header: TRUE )){
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		vuln = TRUE;
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

