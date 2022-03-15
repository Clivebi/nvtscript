if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900179" );
	script_version( "2021-10-04T14:22:38+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_cve_id( "CVE-2008-5161" );
	script_bugtraq_id( 32319 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_name( "OpenSSH CBC Mode Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32760/" );
	script_xref( name: "URL", value: "http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt" );
	script_tag( name: "impact", value: "Successful exploits will allow attackers to obtain four bytes of plaintext from
  an encrypted session." );
	script_tag( name: "affected", value: "- SSH Communications Security Tectia Client and Server version 6.0.4 and prior

  - SSH Communications Security Tectia ConnectSecure version 6.0.4 and prior

  - OpenSSH version prior to 5.2" );
	script_tag( name: "insight", value: "The flaw is due to the improper handling of errors within an SSH session
  encrypted with a block cipher algorithm in the Cipher-Block Chaining 'CBC' mode." );
	script_tag( name: "solution", value: "Update to version 5.2 or later." );
	script_tag( name: "summary", value: "OpenSSH is prone to information disclosure vulnerability.

  This NVT has been replaced by NVT 'OpenSSH CBC Mode Information Disclosure Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.100153)." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

