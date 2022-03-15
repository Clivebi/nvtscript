if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704167" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2018-1000097" );
	script_name( "Debian Security Advisory DSA 4167-1 (sharutils - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-05 00:00:00 +0200 (Thu, 05 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-13 14:50:00 +0000 (Fri, 13 Apr 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4167.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "sharutils on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1:4.14-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1:4.15.2-2+deb9u1.

We recommend that you upgrade your sharutils packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/sharutils" );
	script_tag( name: "summary", value: "A buffer-overflow vulnerability was discovered in Sharutils, a set of
utilities handle Shell Archives. An attacker with control on the input of
the unshar command, could crash the application or execute arbitrary code
in the its context." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sharutils", ver: "1:4.14-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sharutils-doc", ver: "1:4.14-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sharutils", ver: "1:4.15.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sharutils-doc", ver: "1:4.15.2-2+deb9u1", rls: "DEB9" ) )){
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

