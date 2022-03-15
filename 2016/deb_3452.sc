if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703452" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2015-8614" );
	script_name( "Debian Security Advisory DSA 3452-1 (claws-mail - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-23 00:00:00 +0100 (Sat, 23 Jan 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3452.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "claws-mail on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 3.8.1-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 3.11.1-3+deb8u1.

We recommend that you upgrade your claws-mail packages." );
	script_tag( name: "summary", value: "DrWhax
of the Tails project reported that Claws Mail is missing
range checks in some text conversion functions. A remote attacker
could exploit this to run arbitrary code under the account of a user
that receives a message from them using Claws Mail." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "claws-mail", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-bogofilter", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-dbg", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-doc", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-i18n", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-pgpinline", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-pgpmime", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-plugins", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-smime-plugin", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-spamassassin", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-tools", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-trayicon", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libclaws-mail-dev", ver: "3.8.1-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-acpi-notifier", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-address-keeper", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-archiver-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-attach-remover", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-attach-warner", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-bogofilter", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-bsfilter-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-clamd-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-dbg", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-doc", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-extra-plugins", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-fancy-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-feeds-reader", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-fetchinfo-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-gdata-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-i18n", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-libravatar", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-mailmbox-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-multi-notifier", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-newmail-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-pdf-viewer", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-perl-filter", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-pgpinline", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-pgpmime", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-plugins", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-python-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-smime-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-spam-report", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-spamassassin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-tnef-parser", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-tools", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "claws-mail-vcalendar-plugin", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libclaws-mail-dev", ver: "3.11.1-3+deb8u1", rls: "DEB8" ) ) != NULL){
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

