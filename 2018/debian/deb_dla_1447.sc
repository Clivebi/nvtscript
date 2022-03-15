if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891447" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-14062" );
	script_name( "Debian LTS: Security Advisory for libidn (DLA-1447-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-30 00:00:00 +0200 (Mon, 30 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 20:17:00 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00040.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libidn on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.29-1+deb8u3.

We recommend that you upgrade your libidn packages." );
	script_tag( name: "summary", value: "An integer overflow vulnerability was discovered in libidn, the GNU library for
Internationalized Domain Names (IDNs), in its Punycode handling (a Unicode
characters to ASCII encoding) allowing a remote attacker to cause a denial of
service against applications using the library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idn", ver: "1.29-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libidn11", ver: "1.29-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libidn11-dev", ver: "1.29-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libidn11-java", ver: "1.29-1+deb8u3", rls: "DEB8" ) )){
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
