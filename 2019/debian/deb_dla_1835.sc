if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891835" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-14647", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-29 12:15:00 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-06-26 02:00:25 +0000 (Wed, 26 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for python3.4 (DLA-1835-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1835-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/921039" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924072" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3.4'
  package(s) announced via the DLA-1835-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in Python, an interactive
high-level object-oriented language, including

CVE-2018-14647

Python's elementtree C accelerator failed to initialise Expat's hash
salt during initialization. This could make it easy to conduct
denial of service attacks against Expat by constructing an XML
document that would cause pathological hash collisions in Expat's
internal data structures, consuming large amounts CPU and RAM.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization resulting in information disclosure
(credentials, cookies, etc. that are cached against a given
hostname). A specially crafted URL could be incorrectly parsed to
locate cookies or authentication data and send that information to
a different host than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib where CRLF injection is possible
if the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \\r\\n (specifically in
the query string after a ? character) followed by an HTTP header or
a Redis command.

CVE-2019-9947

An issue was discovered in urllib where CRLF injection is possible
if the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \\r\\n (specifically in
the path component of a URL that lacks a ? character) followed by an
HTTP header or a Redis command. This is similar to the CVE-2019-9740
query string issue." );
	script_tag( name: "affected", value: "'python3.4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-1+deb8u3.

We recommend that you upgrade your python3.4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idle-python3.4", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dbg", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dev", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-minimal", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-stdlib", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-testsuite", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dbg", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dev", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-doc", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-examples", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-minimal", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-venv", ver: "3.4.2-1+deb8u3", rls: "DEB8" ) )){
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

