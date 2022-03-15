if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891374" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-11509" );
	script_name( "Debian LTS: Security Advisory for firebird2.5 (DLA-1374-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-14 00:00:00 +0200 (Mon, 14 May 2018)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-29 18:15:00 +0000 (Sat, 29 Feb 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/05/msg00005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "firebird2.5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.5.2.26540.ds4-1~deb7u4.

We recommend that you upgrade your firebird2.5 packages." );
	script_tag( name: "summary", value: "An authenticated remote attacker can execute arbitrary code in Firebird SQL
Server versions 2.5.7 and 3.0.2 by executing a malformed SQL statement. The
only known solution is to disable external UDF libraries from being loaded. In
order to achieve this, the default configuration has changed to UdfAccess=None.
This will prevent the fbudf module from being loaded, but may also break other
functionality relying on modules." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "firebird-dev", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-classic", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-classic-common", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-classic-dbg", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-common", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-common-doc", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-doc", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-examples", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-server-common", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-super", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-super-dbg", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firebird2.5-superclassic", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfbclient2", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfbclient2-dbg", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfbembed2.5", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libib-util", ver: "2.5.2.26540.ds4-1~deb7u4", rls: "DEB7" ) )){
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

