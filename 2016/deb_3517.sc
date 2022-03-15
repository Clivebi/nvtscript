if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703517" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-1531" );
	script_name( "Debian Security Advisory DSA 3517-1 (exim4 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-14 00:00:00 +0100 (Mon, 14 Mar 2016)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3517.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8|9)" );
	script_tag( name: "affected", value: "exim4 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 4.80-7+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 4.84.2-1.

For the testing distribution (stretch), this problem has been fixed
in version 4.86.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 4.86.2-1.

We recommend that you upgrade your exim4 packages." );
	script_tag( name: "summary", value: "A local root privilege escalation
vulnerability was found in Exim, Debian's default mail transfer agent, in
configurations using the perl_startup option (Only Exim via
exim4-daemon-heavy enables Perl support).

To address the vulnerability, updated Exim versions clean the complete
execution environment by default, affecting Exim and subprocesses such
as transports calling other programs, and thus may break existing
installations. New configuration options (keep_environment,
add_environment) were introduced to adjust this behavior." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "exim4", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.80-7+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.84.2-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.86.2-1", rls: "DEB9" ) ) != NULL){
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

