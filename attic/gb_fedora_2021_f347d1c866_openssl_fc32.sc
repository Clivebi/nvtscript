if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818224" );
	script_version( "2021-06-30T12:31:06+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-30 12:31:06 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-04 03:04:25 +0000 (Sun, 04 Apr 2021)" );
	script_name( "Fedora: Security Advisory for openssl (FEDORA-2021-f347d1c866)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-f347d1c866" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TRAH33T2DJLBKQBNRXM5DYUTPXFJ6TC5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the FEDORA-2021-f347d1c866 advisory.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols." );
	script_tag( name: "affected", value: "'openssl' package(s) on Fedora 32." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

