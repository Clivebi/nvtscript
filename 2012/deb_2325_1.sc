if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70540" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-4062" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:26:03 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2325-1 (kfreebsd-8)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202325-1" );
	script_tag( name: "insight", value: "Buffer overflow in the linux emulation support in FreeBSD kernel
allows local users to cause a denial of service (panic) and possibly
execute arbitrary code by calling the bind system call with a long path
for a UNIX-domain socket, which is not properly handled when the
address is used by other unspecified system calls.

For the stable distribution (squeeze), this problem has been fixed in
version 8.1+dfsg-8+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 8.2-9." );
	script_tag( name: "solution", value: "We recommend that you upgrade your kfreebsd-8 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to kfreebsd-8
announced via advisory DSA 2325-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-486", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-686", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-686-smp", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8-amd64", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-486", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-686", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-686-smp", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-8.1-1-amd64", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-486", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-686", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-686-smp", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8-amd64", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-486", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-686", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-686-smp", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-8.1-1-amd64", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-source-8.1", ver: "8.1+dfsg-8+squeeze2", rls: "DEB6" ) ) != NULL){
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

