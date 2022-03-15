if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891017" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2017-10683" );
	script_name( "Debian LTS: Security Advisory for mpg123 (DLA-1017-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-05 00:00:00 +0100 (Mon, 05 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-03 16:53:00 +0000 (Tue, 03 Mar 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00009.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mpg123 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in mpg123 version
1.14.4-1+deb7u2.

We recommend that you upgrade your mpg123 packages." );
	script_tag( name: "summary", value: "It was discovered that there was a remote denial of service vulnerability in
the mpg123 audio library/player. This was caused by a heap-based buffer
over-read in the 'convert_latin1' function." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmpg123-0", ver: "1.14.4-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmpg123-dev", ver: "1.14.4-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mpg123", ver: "1.14.4-1+deb7u2", rls: "DEB7" ) )){
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

