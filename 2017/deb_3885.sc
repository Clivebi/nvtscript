if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703885" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-9468", "CVE-2017-9469" );
	script_name( "Debian Security Advisory DSA 3885-1 (irssi - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-18 00:00:00 +0200 (Sun, 18 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-14 18:45:00 +0000 (Thu, 14 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3885.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "irssi on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 0.8.17-1+deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 1.0.2-1+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.3-1.

We recommend that you upgrade your irssi packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Irssi, a terminal based
IRC client. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2017-9468
Joseph Bisch discovered that Irssi does not properly handle DCC
messages without source nick/host. A malicious IRC server can take
advantage of this flaw to cause Irssi to crash, resulting in a
denial of service.

CVE-2017-9469
Joseph Bisch discovered that Irssi does not properly handle
receiving incorrectly quoted DCC files. A remote attacker can take
advantage of this flaw to cause Irssi to crash, resulting in a
denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "irssi", ver: "0.8.17-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "irssi-dbg", ver: "0.8.17-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "irssi-dev", ver: "0.8.17-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "irssi", ver: "1.0.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "irssi-dev", ver: "1.0.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
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

