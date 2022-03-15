if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803575" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:01:04 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: socks-open-proxy" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Checks if an open socks proxy is running on the target.

The script attempts to connect to a proxy server and send socks4 and socks5 payloads. It is
considered an open proxy if the script receives a Request Granted response from the target port.

The payloads try to open a connection to www.google.com port 80.  A different test host can be
passed as 'proxy.url' argument.

SYNTAX:

proxy.url:  URL that will be requested to the proxy.

proxy.pattern:  Pattern that will be searched inside the request results." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

