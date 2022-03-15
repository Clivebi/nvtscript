if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702774" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4402", "CVE-2013-4351" );
	script_name( "Debian Security Advisory DSA 2774-1 (gnupg2 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-10 00:00:00 +0200 (Thu, 10 Oct 2013)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2774.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "gnupg2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 2.0.14-2+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 2.0.19-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.0.22-1.

We recommend that you upgrade your gnupg2 packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in GnuPG 2, the GNU privacy guard,
a free PGP replacement. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2013-4351When a key or subkey had its key flags subpacket set to all bits
off, GnuPG currently would treat the key as having all bits set.
That is, where the owner wanted to indicate no use permitted,
GnuPG would interpret it as all use permitted. Such no use
permitted
keys are rare and only used in very special circumstances.

CVE-2013-4402
Infinite recursion in the compressed packet parser was possible
with crafted input data, which may be used to cause a denial of
service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnupg-agent", ver: "2.0.14-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.14-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgsm", ver: "2.0.14-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg-agent", ver: "2.0.19-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.19-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgsm", ver: "2.0.19-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scdaemon", ver: "2.0.19-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

