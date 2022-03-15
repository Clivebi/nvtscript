if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891788" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-16860" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-14 12:15:00 +0000 (Wed, 14 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-05-16 02:00:18 +0000 (Thu, 16 May 2019)" );
	script_name( "Debian LTS: Security Advisory for samba (DLA-1788-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00016.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1788-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the DLA-1788-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Isaac Boukris and Andrew Bartlett discovered that the S4U2Self Kerberos
extension used in Samba's Active Directory support was susceptible to
man-in-the-middle attacks caused by incomplete checksum validation." );
	script_tag( name: "affected", value: "'samba' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2:4.2.14+dfsg-0+deb8u13.

We recommend that you upgrade your samba packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ctdb", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-winbind", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libparse-pidl-perl", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-samba", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "registry-tools", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dbg", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dev", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-doc", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dsdb-modules", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-libs", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-testsuite", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-vfs-modules", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "smbclient", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "winbind", ver: "2:4.2.14+dfsg-0+deb8u13", rls: "DEB8" ) )){
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
exit( 0 );

