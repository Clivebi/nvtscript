if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891483" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2018-10871", "CVE-2018-10935" );
	script_name( "Debian LTS: Security Advisory for 389-ds-base (DLA-1483-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00032.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "389-ds-base on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.3.3.5-4+deb8u2.

We recommend that you upgrade your 389-ds-base packages." );
	script_tag( name: "summary", value: "CVE-2018-10871

By default nsslapd-unhashed-pw-switch was set to 'on'. So a copy of
the unhashed password was kept in modifiers and was possibly logged in
changelog and retroCL.

Unless it is used by some plugin it does not require to keep unhashed
passwords. The nsslapd-unhashed-pw-switch option is now 'off' by
default.

CVE-2018-10935

It was discovered that any authenticated user doing a search using
ldapsearch with extended controls for server side sorting could bring
down the LDAP server itself.

The fix is to check if we are able to index the provided value. If we
are not, then slapd_qsort returns an error (LDAP_OPERATION_ERROR) ." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "389-ds", ver: "1.3.3.5-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base", ver: "1.3.3.5-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-dbg", ver: "1.3.3.5-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-dev", ver: "1.3.3.5-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-libs", ver: "1.3.3.5-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-libs-dbg", ver: "1.3.3.5-4+deb8u2", rls: "DEB8" ) )){
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

