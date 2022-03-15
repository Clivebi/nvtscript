if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703382" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-8958", "CVE-2014-9218", "CVE-2015-2206", "CVE-2015-3902", "CVE-2015-3903", "CVE-2015-6830", "CVE-2015-7873" );
	script_name( "Debian Security Advisory DSA 3382-1 (phpmyadmin - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-10-28 00:00:00 +0100 (Wed, 28 Oct 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3382.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "phpmyadmin on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 4:3.4.11.1-2+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 4:4.2.12-2+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.5.1-1.

We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "summary", value: "Several issues have been fixed
in phpMyAdmin, the web administration tool for MySQL.

CVE-2014-8958 (Wheezy only)

Multiple cross-site scripting (XSS) vulnerabilities.

CVE-2014-9218 (Wheezy only)

Denial of service (resource consumption) via a long password.

CVE-2015-2206
Risk of BREACH attack due to reflected parameter.

CVE-2015-3902
XSRF/CSRF vulnerability in phpMyAdmin setup.

CVE-2015-3903 (Jessie only)

Vulnerability allowing man-in-the-middle attack on API call to GitHub.

CVE-2015-6830 (Jessie only)

Vulnerability that allows bypassing the reCaptcha test.

CVE-2015-7873 (Jessie only)

Content spoofing vulnerability when redirecting user to an
external site." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:3.4.11.1-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:4.2.12-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

