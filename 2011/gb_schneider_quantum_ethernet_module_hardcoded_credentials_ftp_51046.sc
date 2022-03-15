if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103366" );
	script_bugtraq_id( 51046 );
	script_cve_id( "CVE-2011-4859", "CVE-2011-4860", "CVE-2011-4861" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Schneider Electric Quantum Ethernet Module Hardcoded Credentials Authentication Bypass Vulnerability" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-14 10:13:05 +0100 (Wed, 14 Dec 2011)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ftp_ready_banner/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51046" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-346-01.pdf" );
	script_xref( name: "URL", value: "http://reversemode.com/index.php?option=com_content&task=view&id=80&Itemid=1" );
	script_tag( name: "summary", value: "Schneider Electric Quantum Ethernet Module is prone to an authentication-
  bypass vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to gain access to the Telnet port
  service, Windriver Debug port service, and FTP service. Attackers can exploit this vulnerability to
  execute arbitrary code within the context of the vulnerable device." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "220 FTP server ready" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
close( soc );
credentials = make_array( "pcfactory", "pcfactory", "loader", "fwdownload", "ntpupdate", "ntpupdate", "sysdiag", "factorycast@schneider", "test", "testingpw", "USER", "USER", "USER", "USERUSER", "webserver", "webpages", "fdrusers", "sresurdf", "nic2212", "poiuypoiuy", "nimrohs2212", "qwertyqwerty", "nip2212", "fcsdfcsd", "ftpuser", "ftpuser", "noe77111_v500", "RcSyyebczS", "AUTCSE", "RybQRceeSd", "AUT_CSE", "cQdd9debez", "target", "RcQbRbzRyc" );
for credential in keys( credentials ) {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	if(ftp_authenticate( socket: soc, user: credential, pass: credentials[credential] )){
		result = ftp_send_cmd( socket: soc, cmd: NASLString( "syst" ) );
		if(!ContainsString( result, "VxWorks" )){
			continue;
		}
		report = NASLString( "It was possible to login via FTP into the remote host using the following\\nUsername/Password combination:\\n\\n", credential, ":", credentials[credential], "\\n\\nWhich produces the following output for the 'syst' command:\\n\\n", result, "\\n" );
		security_message( port: port, data: report );
		close( soc );
		exit( 0 );
	}
	close( soc );
}
exit( 99 );

