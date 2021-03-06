if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68703" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3864" );
	script_name( "FreeBSD Ports: openssl" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: openssl

CVE-2010-3864
Multiple race conditions in ssl/t1_lib.c in OpenSSL 0.9.8f through
0.9.8o, 1.0.0, and 1.0.0a, when multi-threading and internal caching
are enabled on a TLS server, might allow remote attackers to execute
arbitrary code via client data that triggers a heap-based buffer
overflow, related to (1) the TLS server name extension and (2)
elliptic curve cryptography." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://openssl.org/news/secadv_20101116.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/3042c33a-f237-11df-9d02-0018fe623f2b.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "openssl" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.0.0_2" ) < 0){
	txt += "Package openssl version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

