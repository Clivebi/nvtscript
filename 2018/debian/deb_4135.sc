if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704135" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2018-1050", "CVE-2018-1057" );
	script_name( "Debian Security Advisory DSA 4135-1 (samba - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-13 00:00:00 +0100 (Tue, 13 Mar 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 14:54:00 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4135.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "samba on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), CVE-2018-1050 will be addressed
in a later update. Unfortunately the changes required to fix
CVE-2018-1057 for Debian oldstable are too invasive to be backported.
Users using Samba as an AD-compatible domain controller are encouraged
to apply the workaround described in the Samba wiki and upgrade to
Debian stretch.

For the stable distribution (stretch), these problems have been fixed in
version 2:4.5.12+dfsg-2+deb9u2.

We recommend that you upgrade your samba packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/samba" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following issues:

CVE-2018-1050
It was discovered that Samba is prone to a denial of service
attack when the RPC spoolss service is configured to be run as an
external daemon.

CVE-2018-1057
Bjoern Baumbach from Sernet discovered that on Samba 4 AD DC the
LDAP server incorrectly validates permissions to modify passwords
over LDAP allowing authenticated users to change any other users
passwords, including administrative users." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ctdb", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-winbind", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libparse-pidl-perl", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-samba", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "registry-tools", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dev", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dsdb-modules", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-libs", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-testsuite", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-vfs-modules", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "smbclient", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "winbind", ver: "2:4.5.12+dfsg-2+deb9u2", rls: "DEB9" ) )){
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

