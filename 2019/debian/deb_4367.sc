if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704367" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-16864", "CVE-2018-16865", "CVE-2018-16866" );
	script_name( "Debian Security Advisory DSA 4367-1 (systemd - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-13 00:00:00 +0100 (Sun, 13 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4367.html" );
	script_xref( name: "URL", value: "https://www.qualys.com/2019/01/09/system-down/system-down.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "systemd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 232-25+deb9u7.

We recommend that you upgrade your systemd packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/systemd" );
	script_tag( name: "summary", value: "The Qualys Research Labs discovered multiple vulnerabilities in
systemd-journald. Two memory corruption flaws, via attacker-controlled
allocations using the alloca function (CVE-2018-16864,
CVE-2018-16865)
and an out-of-bounds read flaw leading to an information leak
(CVE-2018-16866),
could allow an attacker to cause a denial of service or the execution of
arbitrary code.

Further details in the Qualys Security Advisory at the linked references." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss-myhostname", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-mymachines", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-resolve", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-systemd", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-systemd", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-dev", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd0", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libudev-dev", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libudev1", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-container", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-coredump", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-journal-remote", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-sysv", ver: "232-25+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "udev", ver: "232-25+deb9u7", rls: "DEB9" ) )){
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

