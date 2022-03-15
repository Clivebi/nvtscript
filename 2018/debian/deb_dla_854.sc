if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890854" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-6009", "CVE-2017-6010", "CVE-2017-6011" );
	script_name( "Debian LTS: Security Advisory for icoutils (DLA-854-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 19:52:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "icoutils on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.29.1-5deb7u2.

We recommend that you upgrade your icoutils packages." );
	script_tag( name: "summary", value: "Icoutils is a set of programs that deal with MS Windows icons and
cursors. Resources such as icons and cursors can be extracted from
MS Windows executable and library files with wrestool.

Three vulnerabilities has been found in these tools.

CVE-2017-6009

A buffer overflow was observed in wrestool.

CVE-2017-6010

A buffer overflow was observed in the extract_icons function.
This issue can be triggered by processing a corrupted ico file
and will result in an icotool crash.

CVE-2017-6011

An out-of-bounds read leading to a buffer overflow was observed
icotool." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "icoutils", ver: "0.29.1-5deb7u2", rls: "DEB7" ) )){
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

