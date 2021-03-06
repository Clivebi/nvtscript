if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703983" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2017-12150", "CVE-2017-12151", "CVE-2017-12163" );
	script_name( "Debian Security Advisory DSA 3983-1 (samba - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-22 00:00:00 +0200 (Fri, 22 Sep 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3983.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "samba on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2:4.2.14+dfsg-0+deb8u8.

For the stable distribution (stretch), these problems have been fixed in
version 2:4.5.8+dfsg-2+deb9u2.

We recommend that you upgrade your samba packages." );
	script_tag( name: "summary", value: "Multiple security issues have been discoverd in Samba, a SMB/CIFS file,
print, and login server for Unix:

CVE-2017-12150
Stefan Metzmacher discovered multiple code paths where SMB signing
was not enforced.

CVE-2017-12151
Stefan Metzmacher discovered that tools using libsmbclient did not
enforce encryption when following DFS redirects, which could allow a
man-in-the-middle attacker to read or modify connections which were
meant to be encrypted.

CVE-2017-12163
Yihan Lian and Zhibin Hu discovered that insufficient range checks
in the processing of SMB1 write requests could result in disclosure
of server memory." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ctdb", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss-winbind", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libparse-pidl-perl", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-samba", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "registry-tools", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dbg", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dev", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dsdb-modules", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-libs", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-testsuite", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-vfs-modules", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbclient", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "winbind", ver: "2:4.2.14+dfsg-0+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ctdb", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss-winbind", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libparse-pidl-perl", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-samba", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "registry-tools", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dev", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dsdb-modules", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-libs", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-testsuite", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-vfs-modules", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbclient", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "winbind", ver: "2:4.5.8+dfsg-2+deb9u2", rls: "DEB9" ) ) != NULL){
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

