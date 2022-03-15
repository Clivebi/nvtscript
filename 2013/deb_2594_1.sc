if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702594" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-3221" );
	script_name( "Debian Security Advisory DSA 2594-1 (virtualbox-ose - programming error)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2594.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "virtualbox-ose on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 3.2.10-dfsg-1+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.1.18-dfsg-1.1 of
the virtualbox source package.

We recommend that you upgrade your virtualbox-ose packages." );
	script_tag( name: "summary", value: "halfdog discovered that incorrect interrupt handling in VirtualBox,
a x86 virtualization solution, can lead to denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "virtualbox-ose", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dbg", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dkms", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-fuse", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-dkms", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-source", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-utils", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-x11", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-qt", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-source", ver: "3.2.10-dfsg-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dbg", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dkms", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-fuse", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-dkms", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-source", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-utils", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-x11", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dbg", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dkms", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-fuse", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-dkms", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-source", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-utils", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-x11", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-qt", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-source", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-qt", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-source", ver: "4.1.18-dfsg-1.1", rls: "DEB7" ) ) != NULL){
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

