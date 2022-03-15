if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103239" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-11-02 11:47:00 +0100 (Wed, 02 Nov 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "SSH Brute Force Logins With Default Credentials Reporting" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_END );
	script_family( "Brute force attacks" );
	script_dependencies( "default_ssh_credentials.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "default_ssh_credentials/started" );
	script_tag( name: "summary", value: "It was possible to login into the remote SSH server using default credentials.

  As the VT 'SSH Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108013) might run into a
  timeout the actual reporting of this vulnerability takes place in this VT instead." );
	script_tag( name: "solution", value: "Change the password as soon as possible." );
	script_tag( name: "vuldetect", value: "Reports default credentials detected by the VT 'SSH Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108013)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
credentials = get_kb_list( "default_ssh_credentials/" + port + "/credentials" );
if(!isnull( credentials )){
	report = "It was possible to login with the following credentials <User>:<Password>\n\n";
	credentials = sort( credentials );
	for credential in credentials {
		report += credential + "\n";
		vuln = TRUE;
	}
}
if(vuln){
	c = get_kb_item( "default_ssh_credentials/" + port + "/too_many_logins" );
	if(c){
		report += "\nRemote host accept more than " + c + " logins. This could indicate some error or some \"broken\" device.\nScanner stops testing for default logins at this point.";
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

