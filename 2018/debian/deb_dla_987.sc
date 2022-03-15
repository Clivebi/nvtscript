if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890987" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2015-7686", "CVE-2016-6127", "CVE-2017-5361", "CVE-2017-5943", "CVE-2017-5944" );
	script_name( "Debian LTS: Security Advisory for request-tracker4 (DLA-987-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00016.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "request-tracker4 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.0.7-5+deb7u5.

We recommend that you upgrade your request-tracker4 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Request Tracker, an
extensible trouble-ticket tracking system. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2016-6127

It was discovered that Request Tracker is vulnerable to a cross-site
scripting (XSS) attack if an attacker uploads a malicious file with
a certain content type. Installations which use the
AlwaysDownloadAttachments config setting are unaffected by this
flaw. The applied fix addresses all existent and future uploaded
attachments.

CVE-2017-5361

It was discovered that Request Tracker is vulnerable to timing
side-channel attacks for user passwords.

CVE-2017-5943

It was discovered that Request Tracker is prone to an information
leak of cross-site request forgery (CSRF) verification tokens if a
user is tricked into visiting a specially crafted URL by an
attacker.

CVE-2017-5944

It was discovered that Request Tracker is prone to a remote code
execution vulnerability in the dashboard subscription interface. A
privileged attacker can take advantage of this flaw through
carefully-crafted saved search names to cause unexpected code to be
executed. The applied fix addresses all existent and future saved
searches.

Additionally to the above mentioned CVEs, this update works around
CVE-2015-7686 in Email::Address which could induce a denial of service
of Request Tracker itself." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "request-tracker4", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rt4-apache2", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rt4-clients", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rt4-db-mysql", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rt4-db-postgresql", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rt4-db-sqlite", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rt4-fcgi", ver: "4.0.7-5+deb7u5", rls: "DEB7" ) )){
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

