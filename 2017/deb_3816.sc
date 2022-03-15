if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703816" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-2619" );
	script_name( "Debian Security Advisory DSA 3816-1 (samba - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-23 00:00:00 +0100 (Thu, 23 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3816.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "samba on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2:4.2.14+dfsg-0+deb8u4.

For the unstable distribution (sid), this problem has been fixed in
version 2:4.5.6+dfsg-2.

We recommend that you upgrade your samba packages." );
	script_tag( name: "summary", value: "Jann Horn of Google discovered a time-of-check, time-of-use race
condition in Samba, a SMB/CIFS file, print, and login server for Unix. A
malicious client can take advantage of this flaw by exploiting a symlink
race to access areas of the server file system not exported under a
share definition." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ctdb", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss-winbind", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libparse-pidl-perl", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbsharemodes-dev", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbsharemodes0", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-samba", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "registry-tools", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dbg", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dev", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dsdb-modules", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-libs", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-testsuite", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-vfs-modules", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbclient", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "winbind", ver: "2:4.2.14+dfsg-0+deb8u4", rls: "DEB8" ) ) != NULL){
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

