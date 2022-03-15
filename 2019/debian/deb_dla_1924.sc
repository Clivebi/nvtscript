if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891924" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-16056" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-17 02:00:23 +0000 (Tue, 17 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for python3.4 (DLA-1924-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1924-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3.4'
  package(s) announced via the DLA-1924-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in Python, an interactive high-level
object-oriented language.

CVE-2019-16056

The email module wrongly parses email addresses that contain
multiple @ characters. An application that uses the email module and
implements some kind of checks on the From/To headers of a message
could be tricked into accepting an email address that should be
denied." );
	script_tag( name: "affected", value: "'python3.4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.4.2-1+deb8u7.

We recommend that you upgrade your python3.4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idle-python3.4", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dbg", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dev", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-minimal", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-stdlib", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-testsuite", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dbg", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dev", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-doc", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-examples", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-minimal", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-venv", ver: "3.4.2-1+deb8u7", rls: "DEB8" ) )){
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

