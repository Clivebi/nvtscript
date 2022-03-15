if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702633" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1423" );
	script_name( "Debian Security Advisory DSA 2633-1 (fusionforge - privilege escalation)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-26 00:00:00 +0100 (Tue, 26 Feb 2013)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2633.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "fusionforge on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 5.0.2-5+squeeze2.

For the testing (wheezy) and unstable (sid) distribution, these problems will
be fixed soon.

We recommend that you upgrade your fusionforge packages." );
	script_tag( name: "summary", value: "Helmut Grohne discovered multiple privilege escalation flaws in FusionForge, a
web-based project-management and collaboration software. Most of the
vulnerabilities are related to the bad handling of privileged operations on
user-controlled files or directories." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "fusionforge-full", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fusionforge-minimal", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fusionforge-standard", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-common", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-db-postgresql", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-dns-bind9", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-ftp-proftpd", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-lists-mailman", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-mta-courier", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-mta-exim4", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-mta-postfix", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-contribtracker", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-extratabs", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-globalsearch", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-mediawiki", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-projectlabels", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmarch", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmbzr", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmcvs", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmdarcs", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmgit", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmhg", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-plugin-scmsvn", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-shell-postgresql", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-web-apache", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-web-apache2", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gforge-web-apache2-vhosts", ver: "5.0.2-5+squeeze2", rls: "DEB6" ) ) != NULL){
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

