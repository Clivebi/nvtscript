if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803547" );
	script_version( "2020-07-07T08:05:40+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 08:05:40 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:36 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: pop3-capabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Retrieves POP3 email server capabilities.

POP3 capabilities are defined in RFC 2449. The CAPA command allows a client to ask a server what
commands it supports and possibly any site-specific policy. Besides the list of supported commands,
the IMPLEMENTATION string giving the server version may be available." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

