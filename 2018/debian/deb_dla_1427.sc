if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891427" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-14055", "CVE-2018-14056" );
	script_name( "Debian LTS: Security Advisory for znc (DLA-1427-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-16 00:00:00 +0200 (Mon, 16 Jul 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 17:04:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "znc on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in znc version
1.4-2+deb8u1.

We recommend that you upgrade your znc packages." );
	script_tag( name: "summary", value: "It was discovered that there were two issues in znc, a modular IRC
bouncer:

  * There was insufficient validation of lines coming from the network
allowing a non-admin user to escalate his privilege and inject rogue
values into znc.conf. (CVE-2018-14055)

  * A path traversal vulnerability (via '../' being embedded in a web skin
name) to access files outside of the allowed directory.
(CVE-2018-14056)" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "znc", ver: "1.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "znc-dbg", ver: "1.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "znc-dev", ver: "1.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "znc-perl", ver: "1.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "znc-python", ver: "1.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "znc-tcl", ver: "1.4-2+deb8u1", rls: "DEB8" ) )){
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

