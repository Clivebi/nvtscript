if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891122" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2017-14100" );
	script_name( "Debian LTS: Security Advisory for asterisk (DLA-1122-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "asterisk on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:1.8.13.1~dfsg1-3+deb7u7.

We recommend that you upgrade your asterisk packages." );
	script_tag( name: "summary", value: "security vulnerability was discovered in Asterisk, an Open
Source PBX and telephony toolkit, that may lead to unauthorized
command execution.

The app_minivm module has an 'externnotify' program configuration option
that is executed by the MinivmNotify dialplan application. The
application uses the caller-id name and number as part of a built
string passed to the OS shell for interpretation and execution. Since
the caller-id name and number can come from an untrusted source, a
crafted caller-id name or number allows an arbitrary shell command
injection." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-dahdi", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-mobile", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-modules", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-mp3", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-mysql", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-ooh323", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-voicemail", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-voicemail-imapstorage", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-voicemail-odbcstorage", ver: "1:1.8.13.1~dfsg1-3+deb7u7", rls: "DEB7" ) )){
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

