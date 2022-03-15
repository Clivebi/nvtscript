if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801254" );
	script_version( "2020-11-26T08:02:59+0000" );
	script_cve_id( "CVE-2009-1122", "CVE-2009-1535" );
	script_tag( name: "last_modification", value: "2020-11-26 08:02:59 +0000 (Thu, 26 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-08-10 12:08:05 +0200 (Tue, 10 Aug 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE: IIS WebDAV Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2010 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "This script attempts to check for IIS 5.1 and 6.0 WebDAV
  Authentication Bypass Vulnerability. The vulnerability was patched
  by Microsoft MS09-020 Security patch update.

  This is a wrapper on the Nmap Security Scanner's http-iis-webdav-vuln.nse" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

