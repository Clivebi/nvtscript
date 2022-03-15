if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108975" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-10-26 12:13:27 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Backup File Scanner (HTTP) - Unreliable Detection Reporting" );
	script_category( ACT_END );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_http_backup_file_scan.sc" );
	script_mandatory_keys( "http_backup_file_scan/started" );
	script_tag( name: "summary", value: "The script reports backup files left on the web server.

  Notes:

  - 'Unreliable Detection' means that a file was detected only based on a HTTP 200 (Found) status code reported
  by the remote web server when a file was requested.

  - As the VT 'Backup File Scanner (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.140853) might run into a timeout the actual
  reporting of this vulnerability takes place in this VT instead." );
	script_tag( name: "vuldetect", value: "Reports previous enumerated backup files accessible on the remote web server." );
	script_tag( name: "impact", value: "Based on the information provided in this files an attacker might be able to
  gather sensitive information stored in these files." );
	script_tag( name: "solution", value: "Delete the backup files." );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2017/10/31/1" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
findings = get_kb_list( "www/" + host + "/" + port + "/content/backup_file_unreliable" );
if(findings){
	report = "The following backup files were identified (<URL>:<Matching pattern>):\n";
	findings = sort( findings );
	for finding in findings {
		url_pattern = split( buffer: finding, sep: "#-----#", keep: FALSE );
		if(!url_pattern || max_index( url_pattern ) != 2){
			continue;
		}
		url = url_pattern[0];
		pattern = url_pattern[1];
		report += "\n" + url + ":" + pattern;
		vuln = TRUE;
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

