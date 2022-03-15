if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11229" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpinfo() output Reporting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Randy Matz" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpinfo_output_detect.sc" );
	script_mandatory_keys( "php/phpinfo/detected" );
	script_tag( name: "solution", value: "Delete the listed files or restrict access to them." );
	script_tag( name: "summary", value: "Many PHP installation tutorials instruct the user to create
  a file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often
  left back in the webserver directory." );
	script_tag( name: "impact", value: "Some of the information that can be gathered from this file includes:

  The username of the user running the PHP process, if it is a sudo user, the IP address of the host, the web server
  version, the system version (Unix, Linux, Windows, ...), and the root directory of the web server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
report = "The following files are calling the function phpinfo() which disclose potentially sensitive information:\n";
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(!get_kb_item( "php/phpinfo/" + host + "/" + port + "/detected" )){
	exit( 99 );
}
url_list = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/reporting" );
if(!is_array( url_list )){
	exit( 99 );
}
url_list = sort( url_list );
for url in url_list {
	report += "\n" + url;
}
security_message( port: port, data: report );
exit( 0 );

