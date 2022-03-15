if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104108" );
	script_version( "2020-11-12T09:56:04+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:56:04 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: smtp-open-relay" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal of this
script is to tell if a SMTP server is vulnerable to mail relaying.

An SMTP server that works as an open relay, is an email server that does not verify if the user is
authorised to send email from the specified email address. Therefore, users would be able to send
email originating from any third-party email address that they want.

The checks are done based in combinations of MAIL FROM and RCPT TO commands. The list is hardcoded
in the source file. The script will output all the working combinations that the server allows if
nmap is in verbose mode otherwise the script will print the number of successful tests. The script
will not output if the server requires authentication.

If debug is enabled and an error occurs while testing the target host, the error will be printed
with the list of any combinations that were found prior to the error.

SYNTAX:

smtp-open-relay.ip:  Use this to change the IP address to be used (default is the target IP address)

smtp-open-relay.to:  Define the destination email address to be used (without the domain, default is
relaytest)

smtp-open-relay.from:  Define the source email address to be used (without the domain, default is
antispam)

smtp-open-relay.domain:  Define the domain to be used in the anti-spam tests and EHLO command (default
is nmap.scanme.org)" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

