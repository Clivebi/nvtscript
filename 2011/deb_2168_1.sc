if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69001" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0430", "CVE-2011-0431" );
	script_name( "Debian Security Advisory DSA 2168-1 (openafs)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202168-1" );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered the distributed filesystem AFS:

CVE-2011-0430

Andrew Deason discovered that a double free in the Rx server
process could lead to denial of service or the execution of
arbitrary code.

CVE-2011-0431

It was discovered that insufficient error handling in the
kernel module could lead to denial of service.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.7.dfsg1-6+lenny4. Due to a technical problem with the
buildd infrastructure the update is not yet available, but will be
installed into the archive soon.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.12.1+dfsg-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.14+dfsg-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openafs packages. Note that in order" );
	script_tag( name: "summary", value: "The remote host is missing an update to openafs
announced via advisory DSA 2168-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-client", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.4.7.dfsg1-6+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-client", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.4.12.1+dfsg-4", rls: "DEB6" ) ) != NULL){
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

