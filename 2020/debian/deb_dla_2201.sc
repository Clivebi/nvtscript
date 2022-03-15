if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892201" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-11868" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-06 03:00:05 +0000 (Wed, 06 May 2020)" );
	script_name( "Debian LTS: Security Advisory for ntp (DLA-2201-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2201-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the DLA-2201-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A Denial of Service (DoS) vulnerability was discovered in the network
time protocol server/client, ntp.

ntp allowed an 'off-path' attacker to block unauthenticated
synchronisation via a server mode packet with a spoofed source IP
address because transmissions were rescheduled even if a packet
lacked a valid 'origin timestamp'" );
	script_tag( name: "affected", value: "'ntp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in ntp version
1:4.2.6.p5+dfsg-7+deb8u3.

We recommend that you upgrade your ntp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-7+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ntp-doc", ver: "1:4.2.6.p5+dfsg-7+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ntpdate", ver: "1:4.2.6.p5+dfsg-7+deb8u3", rls: "DEB8" ) )){
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

