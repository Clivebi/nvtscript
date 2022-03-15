if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891297" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-7435", "CVE-2018-7436", "CVE-2018-7437", "CVE-2018-7438", "CVE-2018-7439" );
	script_name( "Debian LTS: Security Advisory for freexl (DLA-1297-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "freexl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0.0b-1+deb7u5.

We recommend that you upgrade your freexl packages." );
	script_tag( name: "summary", value: "Leon reported five heap-based buffer-overflow vulnerabilities in FreeXL.

CVE-2018-7435

    There is a heap-based buffer over-read in the freexl::destroy_cell
    function.

CVE-2018-7436

    There is a heap-based buffer over-read in a pointer dereference of
    the parse_SST function.

CVE-2018-7437

    There is a heap-based buffer over-read in a memcpy call of the
    parse_SST function.

CVE-2018-7438

    There is a heap-based buffer over-read in the parse_unicode_string
    function.

CVE-2018-7439

    There is a heap-based buffer over-read in the function
    read_mini_biff_next_record." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libfreexl-dev", ver: "1.0.0b-1+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreexl1", ver: "1.0.0b-1+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreexl1-dbg", ver: "1.0.0b-1+deb7u5", rls: "DEB7" ) )){
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

