if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891959" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2016-10894" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-15 00:15:00 +0000 (Tue, 15 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-15 02:00:09 +0000 (Tue, 15 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for xtrlock (DLA-1959-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1959-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/830726" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xtrlock'
  package(s) announced via the DLA-1959-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that multitouch devices were not being disabled
by the 'xtrlock' screen locking utility.

xtrlock did not block multitouch events so an attacker could still
input and thus control various programs such as Chromium, etc. via
so-called 'multitouch' events including pan scrolling, 'pinch and
zoom' or even being able to provide regular mouse clicks by
depressing the touchpad once and then clicking with a secondary
finger." );
	script_tag( name: "affected", value: "'xtrlock' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in xtrlock version
2.6+deb8u1. However, this fix does not the situation where an
attacker plugs in a multitouch device *after* the screen has been
locked. For more information on this, please see:

We recommend that you upgrade your xtrlock packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "xtrlock", ver: "2.6+deb8u1", rls: "DEB8" ) )){
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

