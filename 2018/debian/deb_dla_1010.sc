if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891010" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2014-9638", "CVE-2014-9639", "CVE-2014-9640", "CVE-2015-6749" );
	script_name( "Debian LTS: Security Advisory for vorbis-tools (DLA-1010-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-02-05 00:00:00 +0100 (Mon, 05 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "vorbis-tools on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.4.0-1+deb7u1.

We recommend that you upgrade your vorbis-tools packages." );
	script_tag( name: "summary", value: "vorbis-tools is vulnerable to multiple issues that can result in denial
of service.

CVE-2014-9638

Divide by zero error in oggenc with a WAV file whose number of
channels is set to zero.

CVE-2014-9639

Integer overflow in oggenc via a crafted number of channels in a WAV
file, which triggers an out-of-bounds memory access.

CVE-2014-9640

Out-of bounds read in oggenc via a crafted raw file.

CVE-2015-6749

Buffer overflow in the aiff_open function in oggenc/audio.c
via a crafted AIFF file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "vorbis-tools", ver: "1.4.0-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vorbis-tools-dbg", ver: "1.4.0-1+deb7u1", rls: "DEB7" ) )){
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

