if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703345" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-4497", "CVE-2015-4498" );
	script_name( "Debian Security Advisory DSA 3345-1 (iceweasel - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-29 00:00:00 +0200 (Sat, 29 Aug 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3345.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "iceweasel on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 38.2.1esr-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 38.2.1esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 38.2.1esr-1.

We recommend that you upgrade your iceweasel packages." );
	script_tag( name: "summary", value: "Multiple security issues have
been found in Iceweasel, Debian's version of the Mozilla Firefox web browser.
The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-4497
Jean-Max Reymond and Ucha Gobejishvili discovered a use-after-free
vulnerability which occurs when resizing of a canvas element is
triggered in concert with style changes. A web page containing
malicious content can cause Iceweasel to crash, or potentially,
execute arbitrary code with the privileges of the user running
Iceweasel.

CVE-2015-4498
Bas Venis reported a flaw in the handling of add-ons installation. A
remote attacker can take advantage of this flaw to bypass the add-on
installation prompt and trick a user into installing an add-on from
a malicious source." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceweasel", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-dbg", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-dev", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ach", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-af", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-all", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-an", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ar", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-as", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ast", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-az", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-be", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-bg", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-bn-bd", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-bn-in", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-br", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-bs", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ca", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-cs", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-csb", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-cy", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-da", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-de", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-dsb", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-el", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-en-gb", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-en-za", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-eo", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-es-ar", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-es-cl", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-es-es", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-es-mx", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-et", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-eu", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-fa", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ff", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-fi", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-fr", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-fy-nl", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ga-ie", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-gd", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-gl", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-gu-in", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-he", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-hi-in", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-hr", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-hsb", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-hu", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-hy-am", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-id", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-is", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-it", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ja", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-kk", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-km", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-kn", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ko", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ku", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-lij", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-lt", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-lv", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-mai", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-mk", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ml", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-mr", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ms", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-nb-no", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-nl", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-nn-no", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-or", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-pa-in", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-pl", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-pt-br", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-pt-pt", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-rm", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ro", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ru", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-si", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-sk", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-sl", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-son", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-sq", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-sr", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-sv-se", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-ta", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-te", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-th", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-tr", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-uk", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-uz", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-vi", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-xh", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-zh-cn", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-zh-tw", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-l10n-zu", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs17d", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs17d-dbg", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-17.0", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-17.0-dbg", ver: "38.2.1esr-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

