if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703332" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-2213", "CVE-2015-5622", "CVE-2015-5730", "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5734" );
	script_name( "Debian Security Advisory DSA 3332-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-11 00:00:00 +0200 (Tue, 11 Aug 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3332.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 4.1+dfsg-1+deb8u4.

For the unstable distribution (sid), these problems have been fixed in
version 4.2.4+dfsg-1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been fixed in Wordpress, the popular
blogging engine.

CVE-2015-2213
SQL Injection allowed a remote attacker to compromise the site.

CVE-2015-5622
The robustness of the shortcodes HTML tags filter has been
improved. The parsing is a bit more strict, which may affect
your installation. This is the corrected version of the patch
that needed to be reverted in DSA 3328-2.

CVE-2015-5730
A potential timing side-channel attack in widgets.

CVE-2015-5731
An attacker could lock a post that was being edited.

CVE-2015-5732
Cross site scripting in a widget title allows an attacker to
steal sensitive information.

CVE-2015-5734
Fix some broken links in the legacy theme preview.

The issues were discovered by Marc-Alexandre Montpas of Sucuri,
Helen Hou-Sand of the WordPress security team, Netanel Rubin of Check Point,
Ivan Grigorov, Johannes Schmitt of Scrutinizer and Mohamed A. Baset." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress", ver: "4.1+dfsg-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1+dfsg-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1+dfsg-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1+dfsg-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1+dfsg-1+deb8u4", rls: "DEB8" ) ) != NULL){
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

