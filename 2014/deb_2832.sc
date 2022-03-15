if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702832" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2011-4971", "CVE-2013-0179", "CVE-2013-7239" );
	script_name( "Debian Security Advisory DSA 2832-1 (memcached - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-01 00:00:00 +0100 (Wed, 01 Jan 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2832.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "memcached on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed
in version 1.4.5-1+deb6u1. Note that the patch for CVE-2013-7239 was not
applied for the oldstable distribution as SASL support is not enabled in
this version. This update also provides the fix for CVE-2013-0179
which
was fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.13-0.2+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your memcached packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in memcached, a high-performance
memory object caching system. The Common Vulnerabilities and Exposures
project identifies the following issues:

CVE-2011-4971
Stefan Bucur reported that memcached could be caused to crash by
sending a specially crafted packet.

CVE-2013-7239
It was reported that SASL authentication could be bypassed due to a
flaw related to the management of the SASL authentication state. With
a specially crafted request, a remote attacker may be able to
authenticate with invalid SASL credentials." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "memcached", ver: "1.4.5-1+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "memcached", ver: "1.4.13-0.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

