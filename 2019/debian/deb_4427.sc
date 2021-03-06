if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704427" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-3880" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-27 08:29:00 +0000 (Mon, 27 May 2019)" );
	script_tag( name: "creation_date", value: "2019-04-09 02:00:13 +0000 (Tue, 09 Apr 2019)" );
	script_name( "Debian Security Advisory DSA 4427-1 (samba - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4427.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4427-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the DSA-4427-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Michael Hanselmann discovered that Samba, a SMB/CIFS file, print, and
login server for Unix, was vulnerable to a symlink traversal
attack. It would allow remote authenticated users with write
permission to either write or detect files outside of Samba shares." );
	script_tag( name: "affected", value: "'samba' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2:4.5.16+dfsg-1+deb9u1.

We recommend that you upgrade your samba packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ctdb", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-winbind", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libparse-pidl-perl", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-samba", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "registry-tools", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dev", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dsdb-modules", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-libs", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-testsuite", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-vfs-modules", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "smbclient", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "winbind", ver: "2:4.5.16+dfsg-1+deb9u1", rls: "DEB9" ) )){
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

