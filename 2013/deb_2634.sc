if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702634" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-4520", "CVE-2013-1665", "CVE-2013-0306", "CVE-2013-0305" );
	script_name( "Debian Security Advisory DSA 2634-1 (python-django - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-27 00:00:00 +0100 (Wed, 27 Feb 2013)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2634.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "python-django on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 1.2.3-3+squeeze5.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.4-1.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Django, a high-level
Python web development framework. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2012-4520
James Kettle discovered that Django did not properly filter the HTTP
Host header when processing certain requests. An attacker could exploit
this to generate and cause parts of Django, particularly the
password-reset mechanism, to display arbitrary URLs to users.

CVE-2013-0305
Orange Tsai discovered that the bundled administrative interface
of Django could expose supposedly-hidden information via its history
log.

CVE-2013-0306
Mozilla discovered that an attacker can abuse Django's tracking of
the number of forms in a formset to cause a denial-of-service attack
due to extreme memory consumption.

CVE-2013-1665
Michael Koziarski discovered that Django's XML deserialization is
vulnerable to entity-expansion and external-entity/DTD attacks." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.2.3-3+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.2.3-3+squeeze5", rls: "DEB6" ) ) != NULL){
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

