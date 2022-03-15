if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704300" );
	script_version( "2021-06-17T11:57:04+0000" );
	script_cve_id( "CVE-2018-10860" );
	script_name( "Debian Security Advisory DSA 4300-1 (libarchive-zip-perl - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:57:04 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-22 00:00:00 +0200 (Sat, 22 Sep 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-23 10:29:00 +0000 (Sun, 23 Sep 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4300.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "libarchive-zip-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.59-1+deb9u1.

We recommend that you upgrade your libarchive-zip-perl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libarchive-zip-perl" );
	script_tag( name: "summary", value: "It was discovered that Archive::Zip, a perl module for manipulation of
ZIP archives, is prone to a directory traversal vulnerability. An
attacker able to provide a specially crafted archive for processing can
take advantage of this flaw to overwrite arbitrary files during archive
extraction." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libarchive-zip-perl", ver: "1.59-1+deb9u1", rls: "DEB9" ) )){
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

