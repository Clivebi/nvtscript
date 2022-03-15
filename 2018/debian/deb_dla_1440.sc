if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891440" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2018-10860" );
	script_name( "Debian LTS: Security Advisory for libarchive-zip-perl (DLA-1440-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-25 00:00:00 +0200 (Wed, 25 Jul 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-23 10:29:00 +0000 (Sun, 23 Sep 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00032.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libarchive-zip-perl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.39-1+deb8u1.

We recommend that you upgrade your libarchive-zip-perl packages." );
	script_tag( name: "summary", value: "The libarchive-zip-perl package is vulnerable to a directory traversal
attack in Archive::Zip. It was found that the Archive::Zip module did
not properly sanitize paths while extracting zip files. An attacker
able to provide a specially crafted archive for processing could use
this flaw to write or overwrite arbitrary files in the context of the
Perl interpreter." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libarchive-zip-perl", ver: "1.39-1+deb8u1", rls: "DEB8" ) )){
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

