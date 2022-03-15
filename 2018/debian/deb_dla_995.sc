if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890995" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-8400", "CVE-2017-8401" );
	script_name( "Debian LTS: Security Advisory for swftools (DLA-995-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-12 14:58:00 +0000 (Fri, 12 May 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "swftools on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.9.2+ds1-3+deb7u1.

We recommend that you upgrade your swftools packages." );
	script_tag( name: "summary", value: "CVE-2017-8400
In SWFTools 0.9.2, an out-of-bounds write of heap data can occur in
the function png_load() in lib/png.c:755. This issue can be triggered
by a malformed PNG file that is mishandled by png2swf.
Attackers could exploit this issue for DoS, it might cause arbitrary
code execution.

CVE-2017-8401
In SWFTools 0.9.2, an out-of-bounds read of heap data can occur in
the function png_load() in lib/png.c:724. This issue can be triggered
by a malformed PNG file that is mishandled by png2swf.
Attackers could exploit this issue for DoS." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "swftools", ver: "0.9.2+ds1-3+deb7u1", rls: "DEB7" ) )){
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

