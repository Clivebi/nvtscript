if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703143" );
	script_version( "2020-11-12T11:08:16+0000" );
	script_cve_id( "CVE-2015-0377", "CVE-2015-0418" );
	script_name( "Debian Security Advisory DSA 3143-1 (virtualbox - security update)" );
	script_tag( name: "last_modification", value: "2020-11-12 11:08:16 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-01-28 00:00:00 +0100 (Wed, 28 Jan 2015)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3143.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "virtualbox on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 4.1.18-dfsg-2+deb7u4.

For the unstable distribution (sid), these problems have been fixed in
version 4.3.18-dfsg-2.

We recommend that you upgrade your virtualbox packages." );
	script_tag( name: "summary", value: "Two vulnerabilities have been discovered
in VirtualBox, an x86 virtualisation solution, which might result in denial of
service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "virtualbox", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dbg", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dkms", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-fuse", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-dkms", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-source", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-utils", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-x11", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dbg", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dkms", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-fuse", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-dkms", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-source", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-utils", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-x11", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-qt", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-source", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-qt", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-source", ver: "4.1.18-dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
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

