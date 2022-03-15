if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801842" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)" );
	script_cve_id( "CVE-2011-0899" );
	script_bugtraq_id( 46116 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Drupal AES Encryption Module Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://drupal.org/node/1048998" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43185" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65112" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "drupal/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks." );
	script_tag( name: "affected", value: "Drupal AES Encryption Module 7.x-1.4" );
	script_tag( name: "insight", value: "The flaw is triggered when the module saves user passwords in a text file,
  which will disclose the password to a remote attacker who directly requests the file." );
	script_tag( name: "solution", value: "Upgarade to Drupal AES Encryption Module 7.x-1.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running Drupal AES Encryption Module and is prone to
  information disclosure vulnerability." );
	script_xref( name: "URL", value: "http://drupal.org/node/1040728" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(dir = get_dir_from_kb( port: port, app: "drupal" )){
	url = NASLString( dir, "/login_edit_dump.txt" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

