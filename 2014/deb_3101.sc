if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703101" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2013-7401", "CVE-2013-7402" );
	script_name( "Debian Security Advisory DSA 3101-1 (c-icap - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-13 00:00:00 +0100 (Sat, 13 Dec 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3101.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "c-icap on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1:0.1.6-1.1+deb7u1.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 1:0.3.1-1.

For the unstable distribution (sid), these problems have been fixed in
version 1:0.3.1-1.

We recommend that you upgrade your c-icap packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were found in
c-icap, an ICAP server implementation, which could allow a remote attacker to
cause c-icap to crash, or have other, unspecified impacts." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "c-icap", ver: "1:0.1.6-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicapapi-dev", ver: "1:0.1.6-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicapapi0", ver: "1:0.1.6-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicapapi0-dbg", ver: "1:0.1.6-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

