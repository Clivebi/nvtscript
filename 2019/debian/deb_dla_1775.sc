if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891775" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-9826" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-04 14:29:00 +0000 (Sat, 04 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-05 02:00:06 +0000 (Sun, 05 May 2019)" );
	script_name( "Debian LTS: Security Advisory for phpbb3 (DLA-1775-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1775-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpbb3'
  package(s) announced via the DLA-1775-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Colin Snover discovered a denial-of-service vulnerability in phpBB3, a
full-featured web forum. Previous versions allowed users to run searches
that might result in long execution times and load on larger boards when
using the fulltext native search engine. To combat this, further
restrictions were introduced on search queries." );
	script_tag( name: "affected", value: "'phpbb3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.0.12-5+deb8u3.

We recommend that you upgrade your phpbb3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpbb3", ver: "3.0.12-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "phpbb3-l10n", ver: "3.0.12-5+deb8u3", rls: "DEB8" ) )){
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

