if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800836" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2399" );
	script_bugtraq_id( 35521 );
	script_name( "DM FileManager 'album.php' Remote File Inclusion Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dm_filemanager_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dm-filemanager/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35622" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35521/exploit" );
	script_xref( name: "URL", value: "http://www.dutchmonkey.com/?label=Latest+News+%26+Announcements#20090704" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attacker execute arbitrary PHP
  code, and can include arbitrary file from local or external resources when register_globals is enabled." );
	script_tag( name: "affected", value: "DutchMonkey, DM FileManager version 3.9.4 and prior." );
	script_tag( name: "insight", value: "Error exists when input passed to the 'SECURITY_FILE' parameter in 'album.php'
  in 'dm-albums/template/' directory is not properly verified before being used to include files." );
	script_tag( name: "solution", value: "Apply the security patch from the references." );
	script_tag( name: "summary", value: "The host is running DM FileManager and is prone to a remote file
  inclusion vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
cpe_list = make_list( "cpe:/a:dutchmonkey:dm_filemanager",
	 "cpe:/a:dutchmonkey:dm_album" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!infos = get_app_version_and_location( cpe: cpe, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
install_path = path;
if(ContainsString( cpe, "dm_album" )){
	is_dm_album = TRUE;
}
if(path && !safe_checks()){
	if(path == "/"){
		path = "";
	}
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		if( is_dm_album ) {
			url = path + "/template/album.php?SECURITY_FILE=/" + file;
		}
		else {
			url = path + "/dm-albums/template/album.php?SECURITY_FILE=/" + file;
		}
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
if(!vers){
	exit( 0 );
}
if(!is_dm_album && version_is_less_equal( version: vers, test_version: "3.9.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: install_path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(is_dm_album && version_is_less( version: vers, test_version: "1.9.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: install_path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

