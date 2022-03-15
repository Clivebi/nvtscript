if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704377" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-1000018" );
	script_name( "Debian Security Advisory DSA 4377-1 (rssh - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-30 00:00:00 +0100 (Wed, 30 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 19:57:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4377.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "rssh on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2.3.4-5+deb9u1.

We recommend that you upgrade your rssh packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/rssh" );
	script_tag( name: "summary", value: "The ESnet security team discovered a vulnerability in rssh, a restricted
shell that allows users to perform only scp, sftp, cvs, svnserve
(Subversion), rdist and/or rsync operations. Missing validation in the
scp support could result in the bypass of this restriction, allowing the
execution of arbitrary shell commands.

Please note that with the update applied, the -3
option of scp can no
longer be used." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rssh", ver: "2.3.4-5+deb9u1", rls: "DEB9" ) )){
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

