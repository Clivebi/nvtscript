if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892399" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-16121", "CVE-2020-16122" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-18 14:30:00 +0000 (Wed, 18 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-08 03:00:16 +0000 (Thu, 08 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for packagekit (DLA-2399-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2399-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'packagekit'
  package(s) announced via the DLA-2399-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in packagekit, a package
management service.

CVE-2020-16121

Vaisha Bernard discovered that PackageKit incorrectly handled
certain methods. A local attacker could use this issue to learn the
MIME type of any file on the system.

CVE-2020-16122

Sami Niemim?ki discovered that PackageKit incorrectly handled local
deb packages. A local user could possibly use this issue to install
untrusted packages, contrary to expectations." );
	script_tag( name: "affected", value: "'packagekit' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.1.5-2+deb9u2.

We recommend that you upgrade your packagekit packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-packagekitglib-1.0", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-packagekit", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpackagekit-glib2-18", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpackagekit-glib2-dev", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "packagekit", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "packagekit-command-not-found", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "packagekit-docs", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "packagekit-gtk3-module", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "packagekit-tools", ver: "1.1.5-2+deb9u2", rls: "DEB9" ) )){
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

