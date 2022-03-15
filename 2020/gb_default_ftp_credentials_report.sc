if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108718" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-03-05 14:02:28 +0000 (Thu, 05 Mar 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "FTP Brute Force Logins Reporting" );
	script_category( ACT_END );
	script_family( "Brute force attacks" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_default_ftp_credentials.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "default_ftp_credentials/started" );
	script_tag( name: "summary", value: "It was possible to login into the remote FTP server using weak/known credentials.

  As the VT 'FTP Brute Force Logins' (OID: 1.3.6.1.4.1.25623.1.0.108717) might run into a timeout the actual
  reporting of this vulnerability takes place in this VT instead." );
	script_tag( name: "vuldetect", value: "Reports weak/known credentials detected by the VT 'FTP Brute Force Logins'
  (OID: 1.3.6.1.4.1.25623.1.0.108717)." );
	script_tag( name: "solution", value: "Change the password as soon as possible." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
credentials = get_kb_list( "default_ftp_credentials/" + port + "/credentials" );
if(!isnull( credentials )){
	report = "It was possible to login with the following credentials <User>:<Password>\n\n";
	credentials = sort( credentials );
	for credential in credentials {
		report += credential + "\n";
		vuln = TRUE;
	}
}
if(vuln){
	c = get_kb_item( "default_ftp_credentials/" + port + "/too_many_logins" );
	if(c){
		report += "\nRemote host accept more than " + c + " logins. This could indicate some error or some \"broken\" device.\nScanner stops testing for default logins at this point.";
	}
	security_message( port: port, data: chomp( report ) );
	exit( 0 );
}
exit( 99 );

