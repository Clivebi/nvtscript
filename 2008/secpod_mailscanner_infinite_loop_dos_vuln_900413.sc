if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900413" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-10 08:20:26 +0100 (Wed, 10 Dec 2008)" );
	script_bugtraq_id( 32514 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_family( "Denial of Service" );
	script_name( "MailScanner Infinite Loop Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/Advisories/32915" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in a
  crafted message and it can lead to system crash through high CPU resources." );
	script_tag( name: "affected", value: "MailScanner version prior to 4.73.3-1 on all Linux platforms." );
	script_tag( name: "insight", value: "This error is due to an issue in 'Clean' Function in message.pm." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest MailScanner version 4.73.3-1." );
	script_tag( name: "summary", value: "This host is installed with MailScanner and is prone to Denial of
  Service vulnerability." );
	exit( 0 );
}
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(sock){
	ver = ssh_cmd( socket: sock, cmd: "MailScanner -v", timeout: 120 );
	ssh_close_connection();
	if(ContainsString( ver, "MailScanner" )){
		pattern = "MailScanner version ([0-3](\\..*)|4(\\.[0-6]?[0-9](\\..*)?|\\.7[0-2](\\..*)?|\\.73\\.[0-3]))($|[^.0-9])";
		if(egrep( pattern: pattern, string: ver )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

