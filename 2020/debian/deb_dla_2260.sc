if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892260" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2015-8688", "CVE-2016-9928" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-07 18:29:00 +0000 (Wed, 07 Dec 2016)" );
	script_tag( name: "creation_date", value: "2020-06-29 03:00:23 +0000 (Mon, 29 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for mcabber (DLA-2260-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00031.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2260-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mcabber'
  package(s) announced via the DLA-2260-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a 'roster push attack' in mcabber, a
console-based Jabber (XMPP) client. This is identical to CVE-2015-8688 for gajim." );
	script_tag( name: "affected", value: "'mcabber' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.10.2-1+deb8u1.

We recommend that you upgrade your mcabber packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mcabber", ver: "0.10.2-1+deb8u1", rls: "DEB8" ) )){
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

