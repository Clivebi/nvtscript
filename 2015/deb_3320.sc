if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703320" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3282", "CVE-2015-3283", "CVE-2015-3284", "CVE-2015-3285", "CVE-2015-3287" );
	script_name( "Debian Security Advisory DSA 3320-1 (openafs - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-30 00:00:00 +0200 (Thu, 30 Jul 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3320.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openafs on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 1.6.1-3+deb7u3.

For the stable distribution (jessie), these problems have been fixed in
version 1.6.9-2+deb8u3.

We recommend that you upgrade your openafs packages." );
	script_tag( name: "summary", value: "It was discovered that OpenAFS, the implementation of the distributed
filesystem AFS, contained several flaws that could result in
information leak, denial-of-service or kernel panic." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libafsauthent1", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libafsrpc1", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkopenafs1", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-client", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fuse", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.6.1-3+deb7u3", rls: "DEB7" ) ) != NULL){
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

