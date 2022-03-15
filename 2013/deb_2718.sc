if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702718" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2201", "CVE-2013-2205", "CVE-2013-2173", "CVE-2013-2204", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-0235", "CVE-2013-2199", "CVE-2013-2200" );
	script_name( "Debian Security Advisory DSA 2718-1 (wordpress - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-01 00:00:00 +0200 (Mon, 01 Jul 2013)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2718.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.5.2+dfsg-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed in
version 3.5.2+dfsg-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 3.5.2+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 3.5.2+dfsg-1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were identified in WordPress, a web blogging
tool. As the CVEs were allocated from releases announcements and
specific fixes are usually not identified, it has been decided to
upgrade the wordpress package to the latest upstream version instead of
backporting the patches.

This means extra care should be taken when upgrading, especially when
using third-party plugins or themes, since compatibility may have been
impacted along the way. We recommend that users check their install
before doing the upgrade.

CVE-2013-2173
A denial of service was found in the way WordPress performs hash
computation when checking password for protected posts. An attacker
supplying carefully crafted input as a password could make the
platform use excessive CPU usage.

CVE-2013-2199Multiple server-side requests forgery (SSRF) vulnerabilities were
found in the HTTP API. This is related to
CVE-2013-0235
,
which was specific to SSRF in pingback requests and was fixed in 3.5.1.

CVE-2013-2200
Inadequate checking of a user's capabilities could lead to a
privilege escalation, enabling them to publish posts when their
user role should not allow for it and to assign posts to other
authors.

CVE-2013-2201
Multiple cross-side scripting (XSS) vulnerabilities due to badly
escaped input were found in the media files and plugins upload forms.

CVE-2013-2202
XML External Entity Injection (XXE) vulnerability via oEmbed
responses.

CVE-2013-2203
A Full path disclosure (FPD) was found in the file upload mechanism.
If the upload directory is not writable, the error message returned
includes the full directory path.

CVE-2013-2204
Content spoofing via Flash applet in the embedded tinyMCE media
plugin.

CVE-2013-2205
Cross-domain XSS in the embedded SWFupload uploader." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress", ver: "3.5.2+dfsg-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.5.2+dfsg-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress", ver: "3.5.2+dfsg-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.5.2+dfsg-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

