if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703250" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3438", "CVE-2015-3439", "CVE-2015-3440" );
	script_name( "Debian Security Advisory DSA 3250-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-04 00:00:00 +0200 (Mon, 04 May 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3250.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 3.6.1+dfsg-1~deb7u6.

For the stable distribution (jessie), these problems have been fixed in
version 4.1+dfsg-1+deb8u1.

For the testing distribution (stretch), these problems have been fixed in
version 4.2.1+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.2.1+dfsg-1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Multiple security issues have been
discovered in Wordpress, a weblog manager, that could allow remote attackers
to upload files with invalid or unsafe names, mount social engineering attacks
or compromise a site via cross-site scripting, and inject SQL commands." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress", ver: "3.6.1+dfsg-1~deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.6.1+dfsg-1~deb7u6", rls: "DEB7" ) ) != NULL){
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

