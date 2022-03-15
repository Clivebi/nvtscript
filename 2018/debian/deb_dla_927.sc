if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890927" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-5661" );
	script_name( "Debian LTS: Security Advisory for fop (DLA-927-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/04/msg00046.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "fop on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:1.0.dfsg2-6+deb7u1.

We recommend that you upgrade your fop packages." );
	script_tag( name: "summary", value: "In Apache FOP before 2.2, files lying on the filesystem of the server
which uses FOP can be revealed to arbitrary users who send maliciously
formed SVG files. The file types that can be shown depend on the user
context in which the exploitable application is running. If the user is
root a full compromise of the server - including confidential or
sensitive files - would be possible. XXE can also be used to attack the
availability of the server via denial of service as the references
within an xml document can trivially trigger an amplification attack." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "fop", ver: "1:1.0.dfsg2-6+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "fop-doc", ver: "1:1.0.dfsg2-6+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfop-java", ver: "1:1.0.dfsg2-6+deb7u1", rls: "DEB7" ) )){
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

