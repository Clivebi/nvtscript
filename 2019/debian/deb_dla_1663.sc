if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891663" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699", "CVE-2018-20406", "CVE-2019-5010" );
	script_name( "Debian LTS: Security Advisory for python3.4 (DLA-1663-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-07 00:00:00 +0100 (Thu, 07 Feb 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "python3.4 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-1+deb8u2.

We recommend that you upgrade your python3.4 packages." );
	script_tag( name: "summary", value: "This DLA fixes a problem parsing x509 certificates, a pickle integer
overflow, and some other minor issues:

CVE-2016-0772

The smtplib library in CPython does not return an error when StartTLS fails,
which might allow man-in-the-middle attackers to bypass the TLS protections by
leveraging a network position between the client and the registry to block the
StartTLS command, aka a 'StartTLS stripping attack.'

CVE-2016-5636

Integer overflow in the get_data function in zipimport.c in CPython
allows remote attackers to have unspecified impact via a negative data size
value, which triggers a heap-based buffer overflow.

CVE-2016-5699

CRLF injection vulnerability in the HTTPConnection.putheader function in
urllib2 and urllib in CPython allows remote attackers to inject arbitrary HTTP
headers via CRLF sequences in a URL.

CVE-2018-20406

Modules/_pickle.c has an integer overflow via a large LONG_BINPUT value
that is mishandled during a 'resize to twice the size' attempt. This issue
might cause memory exhaustion, but is only relevant if the pickle format is
used for serializing tens or hundreds of gigabytes of data.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idle-python3.4", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dbg", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dev", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-minimal", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-stdlib", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-testsuite", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dbg", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dev", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-doc", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-examples", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-minimal", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-venv", ver: "3.4.2-1+deb8u2", rls: "DEB8" ) )){
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

