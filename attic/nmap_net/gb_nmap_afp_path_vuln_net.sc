if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104146" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2010-0533" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: afp-path-vuln" );
	script_xref( name: "URL", value: "http://www.cqure.net/wp/2010/03/detecting-apple-mac-os-x-afp-vulnerability-cve-2010-0533-with-nmap" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT201222" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.

This script attempts to iterate over all AFP shares on the remote host. For each share it attempts
to access the parent directory by exploiting the directory traversal vulnerability as described in
CVE-2010-0533.

The script reports whether the system is vulnerable or not. In addition it lists the contents of the
parent and child directories to a max depth of 2. When running in verbose mode, all items in the
listed directories are shown.  In non verbose mode, output is limited to the first 5 items. If the
server is not vulnerable, the script will not return any information.

SYNTAX:

afp.password:  The password to use for authentication. (If unset it first attempts to use credentials found by 'afp-brute' then no credentials)

afp.username:  The username to use for authentication. (If unset it first attempts to use credentials found by 'afp-brute' then no credentials)" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

