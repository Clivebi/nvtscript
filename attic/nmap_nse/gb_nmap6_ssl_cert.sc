if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803506" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 18:59:55 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: ssl-cert" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Retrieves a server's SSL certificate. The amount of information printed about the certificate
depends on the verbosity level. With no extra verbosity, the script prints the validity period and
the commonName, organizationName, stateOrProvinceName, and countryName of the subject.

'443/tcp open  https

  ssl-cert:

   Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\\ /stateOrProvinceName=California/countryName=US

   Not valid before: 2009-05-28 00:00:00

   Not valid after:  2010-05-01 23:59:59'

With '-v' it adds the issuer name and fingerprints.

'443/tcp open  https

  ssl-cert:

    Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\\ /stateOrProvinceName=California/countryName=US

    Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\\ /organizationName=VeriSign, Inc./countryName=US

    Not valid before: 2009-05-28 00:00:00

    Not valid after:  2010-05-01 23:59:59

    MD5:   c5b8 7ddd ccc7 537f 8861 b476 078d e8fd

    SHA-1: dc5a cb8b 9eb9 b5de 7117 c536 8c15 0e75 ba88 702e'

With '-vv' it adds the PEM-encoded contents of the entire certificate.

'443/tcp open  https

  ssl-cert:

   Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\\ /stateOrProvinceName=California/countryName=US/serialNumber=3014267\\ /1.3.6.1.4.1.311.60.2.1.3=US/streetAddress=2211 N 1st St\\ /1.3.6.1.4.1.311.60.2.1.2=Delaware/postalCode=95131-2021\\ /localityName=San Jose/organizationalUnitName=Information Systems\\ /2.5.4.15=V1.0, Clause 5.(b)

   Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\\ /organizationName=VeriSign, Inc./countryName=US\\ /organizationalUnitName=Terms of use at https://www.verisign.com/rpa (c)06

   Not valid before: 2009-05-28 00:00:00

   Not valid after:  2010-05-01 23:59:59

   MD5:   c5b8 7ddd ccc7 537f 8861 b476 078d e8fd

  - ----BEGIN CERTIFICATE-----
   MIIFxzCCBK+gAwIBAgIQX02QuADDB7CVjZdooVge+zANBgkqhkiG9w0BAQUFADCB ..." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

