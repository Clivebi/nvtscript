if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702729" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4134", "CVE-2013-4135" );
	script_name( "Debian Security Advisory DSA 2729-1 (openafs - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-28 00:00:00 +0200 (Sun, 28 Jul 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2729.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "openafs on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.4.12.1+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 1.6.1-3+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.6.5-1.

We recommend that you upgrade your openafs packages." );
	script_tag( name: "summary", value: "OpenAFS, the implementation of the distributed filesystem AFS, has been
updated to no longer use DES for the encryption of tickets. Additional
migration steps are needed to fully set the update into effect. For more
information please see the upstream advisory:
OPENAFS-SA-2013-003In addition the encrypt option to the vos
tool was fixed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-client", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.4.12.1+dfsg-4+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libafsauthent1", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libafsrpc1", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkopenafs1", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-client", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fuse", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.6.1-3+deb7u1", rls: "DEB7" ) ) != NULL){
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

