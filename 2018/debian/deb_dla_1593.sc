if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891593" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-19274" );
	script_name( "Debian LTS: Security Advisory for phpbb3 (DLA-1593-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-26 00:00:00 +0100 (Mon, 26 Nov 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "phpbb3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.0.12-5+deb8u2.

We recommend that you upgrade your phpbb3 packages." );
	script_tag( name: "summary", value: "Simon Scannell and Robin Peraglie of RIPS Technologies discovered that
passing an absolute path to a file_exists check in phpBB, a full
featured web forum, allows remote code execution through Object
Injection by employing Phar deserialization when an attacker has access
to the Admin Control Panel with founder permissions.

The fix for this issue resulted in the removal of setting the
ImageMagick path. The GD image library can be used as a replacement
and a new event to generate thumbnails was added, so it is possible to
write an extension that uses a different image library to generate
thumbnails." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpbb3", ver: "3.0.12-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "phpbb3-l10n", ver: "3.0.12-5+deb8u2", rls: "DEB8" ) )){
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

