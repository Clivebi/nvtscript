if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891428" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2015-1854", "CVE-2017-15134", "CVE-2018-1054", "CVE-2018-10850", "CVE-2018-1089" );
	script_name( "Debian LTS: Security Advisory for 389-ds-base (DLA-1428-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-16 00:00:00 +0200 (Mon, 16 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-15 21:29:00 +0000 (Wed, 15 May 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00018.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "389-ds-base on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.3.3.5-4+deb8u1.

We recommend that you upgrade your 389-ds-base packages." );
	script_tag( name: "summary", value: "CVE-2015-1854
A flaw was found while doing authorization of modrdn operations.
An unauthenticated attacker able to issue an ldapmodrdn call to
the directory server could perform unauthorized modifications
of entries in the directory server.

CVE-2017-15134
Improper handling of a search filter in slapi_filter_sprintf()
in slapd/util.c can lead to remote server crash and denial
of service.

CVE-2018-1054
When read access on <attribute_name> is enabled, a flaw in
SetUnicodeStringFromUTF_8 function in collate.c, can lead to
out-of-bounds memory operations.
This might result in a server crash, caused by unauthorized
users.

CVE-2018-1089
Any user (anonymous or authenticated) can crash ns-slapd with a
crafted ldapsearch query with very long filter value.

CVE-2018-10850
Due to a race condition the server could crash in turbo mode
(because of high traffic) or when a worker reads several requests
in the read buffer (more_data). Thus an anonymous attacker could
trigger a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "389-ds", ver: "1.3.3.5-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base", ver: "1.3.3.5-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-dbg", ver: "1.3.3.5-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-dev", ver: "1.3.3.5-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-libs", ver: "1.3.3.5-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-libs-dbg", ver: "1.3.3.5-4+deb8u1", rls: "DEB8" ) )){
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

