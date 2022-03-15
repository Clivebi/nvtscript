if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70415" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)" );
	script_cve_id( "CVE-2011-2895" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Security Advisory (FreeBSD-SA-11:04.compress.asc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdpatchlevel" );
	script_tag( name: "insight", value: "The compress utility reduces the size of files using adaptive Lempel-Ziv
coding, or LZW coding, a lossless data compression algorithm.

Both compress(1) and gzip(1) uses code derived from 4.3BSD compress(1).

The code used to decompress a file created by compress(1) does not do
sufficient boundary checks on compressed code words, allowing reference
beyond the decompression table, which may result in a stack overflow or
an infinite loop when the decompressor encounters a corrupted file." );
	script_tag( name: "solution", value: "Upgrade your system to the appropriate stable release
  or security branch dated after the correction date." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:04.compress.asc" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-11:04.compress.asc" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
if(patchlevelcmp( rel: "7.4", patchlevel: "3" ) < 0){
	vuln = TRUE;
}
if(patchlevelcmp( rel: "7.3", patchlevel: "7" ) < 0){
	vuln = TRUE;
}
if(patchlevelcmp( rel: "8.2", patchlevel: "3" ) < 0){
	vuln = TRUE;
}
if(patchlevelcmp( rel: "8.1", patchlevel: "5" ) < 0){
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

