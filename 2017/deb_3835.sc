if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703835" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_cve_id( "CVE-2016-9013", "CVE-2016-9014", "CVE-2017-7233", "CVE-2017-7234" );
	script_name( "Debian Security Advisory DSA 3835-1 (python-django - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-26 00:00:00 +0200 (Wed, 26 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3835.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "python-django on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.7.11-1+deb8u2.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Django, a high-level Python
web development framework. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2016-9013
Marti Raudsepp reported that a user with a hardcoded password is
created when running tests with an Oracle database.

CVE-2016-9014
Aymeric Augustin discovered that Django does not properly validate
the Host header against settings.ALLOWED_HOSTS when the debug
setting is enabled. A remote attacker can take advantage of this
flaw to perform DNS rebinding attacks.

CVE-2017-7233
It was discovered that is_safe_url() does not properly handle
certain numeric URLs as safe. A remote attacker can take advantage
of this flaw to perform XSS attacks or to use a Django server as an
open redirect.

CVE-2017-7234
Phithon from Chaitin Tech discovered an open redirect vulnerability
in the django.views.static.serve() view. Note that this view is not
intended for production use." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.7.11-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-common", ver: "1.7.11-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.7.11-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-django", ver: "1.7.11-1+deb8u2", rls: "DEB8" ) ) != NULL){
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

