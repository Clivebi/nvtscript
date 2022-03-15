if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892337" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-16056", "CVE-2019-20907", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-23 03:00:10 +0000 (Sun, 23 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for python2.7 (DLA-2337-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00034.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2337-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python2.7'
  package(s) announced via the DLA-2337-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in Python2.7, an interactive
high-level object-oriented language.

CVE-2018-20852

By using a malicious server an attacker might steal cookies that are
meant for other domains.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization resulting in information disclosure
(credentials, cookies, etc. that are cached against a given
hostname). A specially crafted URL could be incorrectly parsed to
locate cookies or authentication data and send that information to
a different host than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib2 where CRLF injection is possible
if the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \\r\\n (specifically in
the query string after a ? character) followed by an HTTP header or
a Redis command.

CVE-2019-9947

An issue was discovered in urllib2 where CRLF injection is possible
if the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \\r\\n (specifically in
the path component of a URL that lacks a ? character) followed by an
HTTP header or a Redis command. This is similar to the CVE-2019-9740
query string issue.

CVE-2019-9948

urllib supports the local_file: scheme, which makes it easier for
remote attackers to bypass protection mechanisms that blacklist
file: URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call.

CVE-2019-10160

A security regression of CVE-2019-9636 was discovered which still
allows an attacker to exploit CVE-2019-9636 by abusing the user and
password parts of a URL. When an application parses user-supplied
URLs to store cookies, authentication credentials, or other kind of
information, it is possible for an attacker to provide specially
crafted URLs to make the application locate host-related information
(e.g. cookies, authentication data) and send them to a different
host than where it should, unlike if the URLs had been correctly
parsed. The result of an attack may vary based on the application.

CVE-2019-16056

The email module wrongly parses email addresses that contain
multiple @ characters. An application that uses the email module and
implements some kind of checks on the From/To headers of a message
could be tricked into accepting an email address that should be
denied.

CVE-2019-20907

Opening a crafted tar file could result in an infinite loop due to
missing header validation." );
	script_tag( name: "affected", value: "'python2.7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.7.13-2+deb9u4.

We recommend that you upgrade your python2.7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idle-python2.7", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-dbg", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-dev", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-minimal", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-stdlib", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-testsuite", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-dbg", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-dev", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-doc", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-examples", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-minimal", ver: "2.7.13-2+deb9u4", rls: "DEB9" ) )){
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

