if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891942" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-16993" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-21 13:34:00 +0000 (Thu, 21 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-10-01 02:00:16 +0000 (Tue, 01 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for phpbb3 (DLA-1942-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00036.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1942-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpbb3'
  package(s) announced via the DLA-1942-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In phpBB, includes/acp/acp_bbcodes.php had improper verification of a
CSRF token on the BBCode page in the Administration Control Panel. An
actual CSRF attack was possible if an attacker also managed to retrieve
the session id of a reauthenticated administrator prior to targeting
them.

The description in this DLA does not match what has been documented in
the changelog.Debian.gz of this package version. After the upload of
phpbb3 3.0.12-5+deb8u4, it became evident that CVE-2019-13776 has not yet
been fixed. The correct fix for CVE-2019-13776 has been identified and
will be shipped in a soon-to-come follow-up security release of phpbb3." );
	script_tag( name: "affected", value: "'phpbb3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.0.12-5+deb8u4.

We recommend that you upgrade your phpbb3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpbb3", ver: "3.0.12-5+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "phpbb3-l10n", ver: "3.0.12-5+deb8u4", rls: "DEB8" ) )){
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

