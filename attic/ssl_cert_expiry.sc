if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15901" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSL/TLS: Certificate Expiry" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_tag( name: "solution", value: "Purchase or generate a new SSL/TLS certificate to replace the existing one." );
	script_tag( name: "summary", value: "The remote server's SSL/TLS certificate has already expired or will expire
  shortly.

  This NVT has been replaced by NVT 'SSL/TLS: Certificate Expired' (OID: 1.3.6.1.4.1.25623.1.0.103955)." );
	script_tag( name: "insight", value: "This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have already expired or will expire shortly." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

