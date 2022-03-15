if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891827" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-12795" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-06-20 02:00:11 +0000 (Thu, 20 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for gvfs (DLA-1827-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1827-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/930376" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gvfs'
  package(s) announced via the DLA-1827-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Simon McVittie discovered a flaw in gvfs, the Gnome Virtual File
  System. The gvfsd daemon opened a private D-Bus server socket without
  configuring an authorization rule. A local attacker could connect to
  this server socket and issue D-Bus method calls.

  (Note that the server socket only accepts a single connection, so the
  attacker would have to discover the server and connect to the socket
  before its owner does.)" );
	script_tag( name: "affected", value: "'gvfs' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
  1.22.2-1+deb8u1.

  We recommend that you upgrade your gvfs packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gvfs", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-backends", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-bin", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-common", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-daemons", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-dbg", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-fuse", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvfs-libs", ver: "1.22.2-1+deb8u1", rls: "DEB8" ) )){
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

