if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891390" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126" );
	script_name( "Debian LTS: Security Advisory for procps (DLA-1390-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-04 00:00:00 +0200 (Mon, 04 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/05/msg00021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "procps on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:3.3.3-3+deb7u1.

We recommend that you upgrade your procps packages.

The Debian LTS team would like to thank Abhijith PA for preparing this update." );
	script_tag( name: "summary", value: "The Qualys Research Labs discovered multiple vulnerabilities in procps,
a set of command line and full screen utilities for browsing procfs. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2018-1122

top read its configuration from the current working directory if no
$HOME was configured. If top were started from a directory writable
by the attacker (such as /tmp) this could result in local privilege
escalation.

CVE-2018-1123

Denial of service against the ps invocation of another user.

CVE-2018-1124

An integer overflow in the file2strvec() function of libprocps could
result in local privilege escalation.

CVE-2018-1125

A stack-based buffer overflow in pgrep could result in denial
of service for a user using pgrep for inspecting a specially
crafted process.

CVE-2018-1126

Incorrect integer size parameters used in wrappers for standard C
allocators could cause integer truncation and lead to integer
overflow issues." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libprocps0", ver: "1:3.3.3-3+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libprocps0-dev", ver: "1:3.3.3-3+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "procps", ver: "1:3.3.3-3+deb7u1", rls: "DEB7" ) )){
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

