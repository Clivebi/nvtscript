if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891505" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2018-1000637" );
	script_name( "Debian LTS: Security Advisory for zutils (DLA-1505-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-17 00:00:00 +0200 (Mon, 17 Sep 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-02 17:10:00 +0000 (Fri, 02 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00016.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "zutils on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in
version 1.3-4+deb8u1.

We recommend that you upgrade your zutils packages." );
	script_tag( name: "summary", value: "zutils version prior to version 1.8-pre2 contains a buffer
overflow vulnerability in zcat which happened with some
input files when the '-v, --show-nonprinting' option was
used (or indirectly enabled). This can result in potential
denial of service or arbitrary code execution. This attack
appear is exploitable via the victim opening a crafted
compressed file and has been fixed in 1.8-pre2." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "zutils", ver: "1.3-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zutils-dbg", ver: "1.3-4+deb8u1", rls: "DEB8" ) )){
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

