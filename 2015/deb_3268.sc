if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703268" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3202" );
	script_name( "Debian Security Advisory DSA 3268-1 (ntfs-3g - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-22 00:00:00 +0200 (Fri, 22 May 2015)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3268.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "ntfs-3g on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed in
version 1:2012.1.15AR.5-2.1+deb7u1. Note that this issue does not affect
the binary packages distributed in Debian in wheezy as ntfs-3g does not
use the embedded fuse-lite library.

For the stable distribution (jessie), this problem has been fixed in
version 1:2014.2.15AR.2-1+deb8u1.

For the testing distribution (stretch) and the unstable distribution
(sid), this problem will be fixed soon.

We recommend that you upgrade your ntfs-3g packages." );
	script_tag( name: "summary", value: "Tavis Ormandy discovered that NTFS-3G, a read-write NTFS driver for
FUSE, does not scrub the environment before executing mount or umount
with elevated privileges. A local user can take advantage of this flaw
to overwrite arbitrary files and gain elevated privileges by accessing
debugging features via the environment that would not normally be safe
for unprivileged users." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2012.1.15AR.5-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-dbg", ver: "1:2012.1.15AR.5-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-dev", ver: "1:2012.1.15AR.5-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-udeb", ver: "1:2012.1.15AR.5-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfsprogs", ver: "1:2012.1.15AR.5-2.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2014.2.15AR.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-dbg", ver: "1:2014.2.15AR.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-dev", ver: "1:2014.2.15AR.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-udeb", ver: "1:2014.2.15AR.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

