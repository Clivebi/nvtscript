if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703562" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2015-0857", "CVE-2015-0858" );
	script_name( "Debian Security Advisory DSA 3562-1 (tardiff - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-01 00:00:00 +0200 (Sun, 01 May 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-05-09 19:26:00 +0000 (Mon, 09 May 2016)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3562.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "tardiff on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 0.1-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 0.1-5 and partially in earlier versions.

We recommend that you upgrade your tardiff packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in tardiff, a tarball comparison tool. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2015-0857
Rainer Mueller and Florian Weimer discovered that tardiff is prone
to shell command injections via shell meta-characters in filenames
in tar files or via shell meta-characters in the tar filename
itself.

CVE-2015-0858
Florian Weimer discovered that tardiff uses predictable temporary
directories for unpacking tarballs. A malicious user can use this
flaw to overwrite files with permissions of the user running the
tardiff command line tool." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tardiff", ver: "0.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

