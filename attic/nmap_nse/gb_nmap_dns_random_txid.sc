if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801689" );
	script_version( "2021-09-20T15:26:26+0000" );
	script_cve_id( "CVE-2008-1447" );
	script_bugtraq_id( 30131 );
	script_tag( name: "last_modification", value: "2021-09-20 15:26:26 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-01-06 14:34:14 +0100 (Thu, 06 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)" );
	script_name( "Nmap NSE: DNS Random TXID" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "This script attempts to check a DNS server for the predictable-TXID
  DNS recursion vulnerability.

  This is a wrapper on the Nmap Security Scanner's dns-random-txid.nse." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

