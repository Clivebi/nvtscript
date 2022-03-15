if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68704" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-2939" );
	script_name( "FreeBSD Security Advisory (FreeBSD-SA-10:10.openssl.asc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdpatchlevel" );
	script_tag( name: "insight", value: "FreeBSD includes software from the OpenSSL Project.  The OpenSSL Project is
a collaborative effort to develop a robust, commercial-grade, full-featured
Open Source toolkit implementing the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a full-strength
general purpose cryptography library.

A race condition exists in the OpenSSL TLS server extension code
parsing when used in a multi-threaded application, which uses
OpenSSL's internal caching mechanism.  The race condition can lead to
a buffer overflow. [CVE-2010-3864]

A double free exists in the SSL client ECDH handling code, when
processing specially crafted public keys with invalid prime
numbers. [CVE-2010-2939]" );
	script_tag( name: "solution", value: "Upgrade your system to the appropriate stable release
  or security branch dated after the correction date." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:10.openssl.asc" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-10:10.openssl.asc" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
if(patchlevelcmp( rel: "8.1", patchlevel: "2" ) < 0){
	vuln = TRUE;
}
if(patchlevelcmp( rel: "8.0", patchlevel: "6" ) < 0){
	vuln = TRUE;
}
if(patchlevelcmp( rel: "7.3", patchlevel: "4" ) < 0){
	vuln = TRUE;
}
if(patchlevelcmp( rel: "7.1", patchlevel: "16" ) < 0){
	vuln = TRUE;
}
if( vuln ){
	security_message( port: 0 );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

