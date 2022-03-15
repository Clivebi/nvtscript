if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891660" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-3463", "CVE-2019-3464" );
	script_name( "Debian LTS: Security Advisory for rssh (DLA-1660-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-07 00:00:00 +0100 (Thu, 07 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 19:57:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "rssh on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.3.4-4+deb8u2.

We recommend that you upgrade your rssh packages." );
	script_tag( name: "summary", value: "More vulnerabilities were found by Nick Cleaton in the rssh code that
could lead to arbitrary code execution under certain circumstances.

CVE-2019-3463

reject rsync --daemon and --config command-line options, which
can be used to run arbitrary commands.

CVE-2019-3464

prevent popt to load a ~/.popt configuration file, leading to
arbitrary command execution" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rssh", ver: "2.3.4-4+deb8u2", rls: "DEB8" ) )){
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

