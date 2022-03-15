if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108554" );
	script_version( "2021-07-22T11:56:11+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-22 11:56:11 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-02-26 13:55:27 +0100 (Tue, 26 Feb 2019)" );
	script_name( "OpenVAS / Greenbone Vulnerability Manager (GVM) Default Credentials (OMP/GMP)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gb_openvas_manager_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/omp_gmp", 9390 );
	script_mandatory_keys( "openvasmd_gvmd/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote OpenVAS / Greenbone Vulnerability Manager (GVM) is
  installed / configured in a way that it has account(s) with default passwords enabled." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Tries to login with known default credentials via the OMP/GMP
  protocol." );
	script_tag( name: "solution", value: "Change the password of the mentioned account(s)." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:openvas:openvas_manager",
	 "cpe:/a:greenbone:greenbone_vulnerability_manager" );
creds = make_array( "admin", "admin", "sadmin", "changeme", "Admin", "openvas", "aDmin", "adminpassword", "gvmadmin", "StrongPass", "observer", "observer", "webadmin", "webadmin", "gmp", "gmp", "omp", "omp" );
report = "It was possible to login using the following credentials (username:password:role):\n";
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "omp_gmp" )){
	exit( 0 );
}
CPE = infos["cpe"];
port = infos["port"];
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
for username in keys( creds ) {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	password = creds[username];
	username = tolower( username );
	req = "<authenticate><credentials><username>" + username + "</username><password>" + password + "</password></credentials></authenticate>";
	send( socket: soc, data: req + "\r\n" );
	res = recv( socket: soc, length: 1024 );
	close( soc );
	if(res && ContainsString( res, "<authenticate_response status=\"200\" status_text=\"OK\">" )){
		role = "unknown";
		_role = eregmatch( string: res, pattern: "<role>(.+)</role>" );
		if(_role[1]){
			role = _role[1];
		}
		vuln = TRUE;
		report += "\n" + username + ":" + password + ":" + role;
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

