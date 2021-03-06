if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703501" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-2381" );
	script_name( "Debian Security Advisory DSA 3501-1 (perl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:36 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-10 13:20:00 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3501.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "perl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 5.14.2-21+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 5.20.2-3+deb8u4.

For the unstable distribution (sid), this problem will be fixed in
version 5.22.1-8.

We recommend that you upgrade your perl packages." );
	script_tag( name: "summary", value: "Stephane Chazelas discovered a bug in the environment handling in Perl.
Perl provides a Perl-space hash variable, %ENV, in which environment
variables can be looked up. If a variable appears twice in envp, only
the last value would appear in %ENV, but getenv would return the first.
Perl's taint security mechanism would be applied to the value in %ENV,
but not to the other rest of the environment. This could result in an
ambiguous environment causing environment variables to be propagated to
subprocesses, despite the protections supposedly offered by taint
checking.

With this update Perl changes the behavior to match the following:

%ENV is populated with the first environment variable, as getenv
would return.Duplicate environment entries are removed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libperl-dev", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl5.20", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-base", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-debug", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-doc", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-modules", ver: "5.20.2-3+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcgi-fast-perl", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl-dev", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl5.14", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-base", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-debug", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-doc", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-modules", ver: "5.14.2-21+deb7u3", rls: "DEB7" ) ) != NULL){
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

