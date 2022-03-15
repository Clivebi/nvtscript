if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704203" );
	script_version( "2021-06-17T11:57:04+0000" );
	script_cve_id( "CVE-2017-17670" );
	script_name( "Debian Security Advisory DSA 4203-1 (vlc - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:57:04 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-17 00:00:00 +0200 (Thu, 17 May 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 15:11:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4203.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "vlc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 3.0.2-0+deb9u1.

We recommend that you upgrade your vlc packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/vlc" );
	script_tag( name: "summary", value: "Hans Jerry Illikainen discovered a type conversion vulnerability in the
MP4 demuxer of the VLC media player, which could result in the execution
of arbitrary code if a malformed media file is played.

This update upgrades VLC in stretch to the new 3.x release series (as
security fixes couldn't be sensibly backported to the 2.x series). In
addition two packages needed to be rebuild to ensure compatibility with
VLC 3, phonon-backend-vlc (0.9.0-2+deb9u1) and goldencheetah
(4.0.0~DEV1607-2+deb9u1).

VLC in jessie cannot be migrated to version 3 due to incompatible
library changes with reverse dependencies and is thus now declared
end-of-life for jessie. We recommend to upgrade to stretch or pick a
different media player if that's not an option." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvlc-bin", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvlc-dev", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvlc5", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvlccore-dev", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvlccore8", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-bin", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-data", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-l10n", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-nox", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-access-extra", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-base", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-fluidsynth", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-jack", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-notify", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-qt", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-samba", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-sdl", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-skins2", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-svg", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-video-output", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-video-splitter", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-visualization", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vlc-plugin-zvbi", ver: "3.0.2-0+deb9u1", rls: "DEB9" ) )){
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

