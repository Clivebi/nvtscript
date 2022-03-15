if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892697" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-28421" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-13 16:15:00 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-30 03:00:12 +0000 (Wed, 30 Jun 2021)" );
	script_name( "Debian LTS: Security Advisory for fluidsynth (DLA-2697-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/06/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2697-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2697-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fluidsynth'
  package(s) announced via the DLA-2697-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability has been found in fluidsynth, a real-time MIDI software
synthesizer.
Using a special crafted soundfont2 file, a use after free vulnerability
might result in arbitrary code execution or a denial of service (DoS)." );
	script_tag( name: "affected", value: "'fluidsynth' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.1.6-4+deb9u1.

We recommend that you upgrade your fluidsynth packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "fluidsynth", ver: "1.1.6-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfluidsynth-dev", ver: "1.1.6-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfluidsynth1", ver: "1.1.6-4+deb9u1", rls: "DEB9" ) )){
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

