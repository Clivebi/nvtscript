if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891412" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-18190", "CVE-2017-18248" );
	script_name( "Debian LTS: Security Advisory for cups (DLA-1412-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "cups on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.7.5-11+deb8u3.

We recommend that you upgrade your cups packages." );
	script_tag( name: "summary", value: "Two vulnerabilities affecting the cups printing server were found
which can lead to arbitrary IPP command execution and denial of
service.

CVE-2017-18190

A localhost.localdomain whitelist entry in valid_host() in
scheduler/client.c in CUPS before 2.2.2 allows remote attackers to
execute arbitrary IPP commands by sending POST requests to the
CUPS daemon in conjunction with DNS rebinding. The
localhost.localdomain name is often resolved via a DNS server
(neither the OS nor the web browser is responsible for ensuring
that localhost.localdomain is 127.0.0.1).

CVE-2017-18248

The add_job function in scheduler/ipp.c in CUPS before 2.2.6, when
D-Bus support is enabled, can be crashed by remote attackers by
sending print jobs with an invalid username, related to a D-Bus
notification." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cups", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-client", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-common", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-core-drivers", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-daemon", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-server-common", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.7.5-11+deb8u3", rls: "DEB8" ) )){
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

