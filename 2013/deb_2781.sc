if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702781" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1445" );
	script_name( "Debian Security Advisory DSA 2781-1 (python-crypto - PRNG not correctly reseeded in some situations)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-18 00:00:00 +0200 (Fri, 18 Oct 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2781.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "python-crypto on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.1.0-2+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 2.6-4+deb7u3.

For the testing distribution (jessie), this problem has been fixed in
version 2.6.1-2.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.1-1.

We recommend that you upgrade your python-crypto packages." );
	script_tag( name: "summary", value: "A cryptographic vulnerability was discovered in the pseudo random number
generator in python-crypto.

In some situations, a race condition could prevent the reseeding of the
generator when multiple processes are forked from the same parent. This would
lead it to generate identical output on all processes, which might leak
sensitive values like cryptographic keys." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-crypto", ver: "2.1.0-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-crypto-dbg", ver: "2.1.0-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-crypto", ver: "2.6-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-crypto-dbg", ver: "2.6-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-crypto-doc", ver: "2.6-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-crypto", ver: "2.6-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-crypto-dbg", ver: "2.6-4+deb7u3", rls: "DEB7" ) ) != NULL){
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

