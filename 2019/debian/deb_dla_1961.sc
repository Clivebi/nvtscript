if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891961" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-14464", "CVE-2019-14496", "CVE-2019-14497" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 00:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-10-22 02:00:41 +0000 (Tue, 22 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for milkytracker (DLA-1961-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1961-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/933964" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'milkytracker'
  package(s) announced via the DLA-1961-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Fredric discovered a couple of buffer overflows in MilkyTracker, of which,
a brief description is given below.

CVE-2019-14464

XMFile::read in XMFile.cpp in milkyplay in MilkyTracker had a heap-based
buffer overflow.

CVE-2019-14496

LoaderXM::load in LoaderXM.cpp in milkyplay in MilkyTracker had a
stack-based buffer overflow.

CVE-2019-14497

ModuleEditor::convertInstrument in tracker/ModuleEditor.cpp in MilkyTracker
had a heap-based buffer overflow." );
	script_tag( name: "affected", value: "'milkytracker' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.90.85+dfsg-2.2+deb8u1.

We recommend that you upgrade your milkytracker packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "milkytracker", ver: "0.90.85+dfsg-2.2+deb8u1", rls: "DEB8" ) )){
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

