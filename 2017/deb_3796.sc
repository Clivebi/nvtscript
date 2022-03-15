if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703796" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_cve_id( "CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743" );
	script_name( "Debian Security Advisory DSA 3796-1 (apache2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-26 00:00:00 +0100 (Sun, 26 Feb 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3796.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "apache2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 2.4.10-10+deb8u8.

For the testing (stretch) and unstable (sid) distributions, these
problems have been fixed in version 2.4.25-1.

We recommend that you upgrade your apache2 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in the Apache2 HTTP server.

CVE-2016-0736
RedTeam Pentesting GmbH discovered that mod_session_crypto was
vulnerable to padding oracle attacks, which could allow an attacker
to guess the session cookie.

CVE-2016-2161
Maksim Malyutin discovered that malicious input to mod_auth_digest
could cause the server to crash, causing a denial of service.

CVE-2016-8743
David Dennerline, of IBM Security's X-Force Researchers, and R�gis
Leroy discovered problems in the way Apache handled a broad pattern
of unusual whitespace patterns in HTTP requests. In some
configurations, this could lead to response splitting or cache
pollution vulnerabilities. To fix these issues, this update makes
Apache httpd be more strict in what HTTP requests it accepts.

If this causes problems with non-conforming clients, some checks can
be relaxed by adding the new directive HttpProtocolOptions unsafe

to the configuration.

This update also fixes the issue where mod_reqtimeout was not enabled
by default on new installations." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apache2", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-data", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dev", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-ssl-dev", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-pristine", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.4.25-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-data", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dev", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-event", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-prefork", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-worker", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-pristine", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-macro", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-proxy-html", ver: "2.4.10-10+deb8u8", rls: "DEB8" ) ) != NULL){
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

