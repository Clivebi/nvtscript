if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892308" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2019-17113" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-02 01:15:00 +0000 (Sun, 02 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-02 03:00:15 +0000 (Sun, 02 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for libopenmpt (DLA-2308-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2308-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the DLA-2308-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In libopenmpt before 0.3.19 and 0.4.x before 0.4.9,
ModPlug_InstrumentName and ModPlug_SampleName in libopenmpt_modplug.c
do not restrict the lengths of libmodplug output-buffer strings in
the C API, leading to a buffer overflow." );
	script_tag( name: "affected", value: "'libopenmpt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.2.7386~beta20.3-3+deb9u4.

We recommend that you upgrade your libopenmpt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-dev", ver: "0.2.7386~beta20.3-3+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-doc", ver: "0.2.7386~beta20.3-3+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-modplug-dev", ver: "0.2.7386~beta20.3-3+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-modplug1", ver: "0.2.7386~beta20.3-3+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt0", ver: "0.2.7386~beta20.3-3+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openmpt123", ver: "0.2.7386~beta20.3-3+deb9u4", rls: "DEB9" ) )){
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

