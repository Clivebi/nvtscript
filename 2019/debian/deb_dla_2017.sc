if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892017" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-13161", "CVE-2019-18610", "CVE-2019-18790" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-04 14:46:00 +0000 (Wed, 04 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-12-01 03:00:09 +0000 (Sun, 01 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for asterisk (DLA-2017-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2017-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'asterisk'
  package(s) announced via the DLA-2017-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities are fixed in Asterisk,
an Open Source PBX and telephony toolkit.

CVE-2019-13161
An attacker was able to crash Asterisk when handling an SDP answer to an
outgoing T.38 re-invite.

CVE-2019-18610
Remote authenticated Asterisk Manager Interface (AMI) users without
system authorization could execute arbitrary system commands.

CVE-2019-18790
A SIP call hijacking vulnerability." );
	script_tag( name: "affected", value: "'asterisk' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1:11.13.1~dfsg-2+deb8u7.

We recommend that you upgrade your asterisk packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "asterisk", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-dahdi", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-mobile", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-modules", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-mp3", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-mysql", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-ooh323", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-voicemail", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-voicemail-imapstorage", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-voicemail-odbcstorage", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "asterisk-vpb", ver: "1:11.13.1~dfsg-2+deb8u7", rls: "DEB8" ) )){
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
exit( 0 );

