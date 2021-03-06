if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703778" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2016-10173" );
	script_name( "Debian Security Advisory DSA 3778-1 (ruby-archive-tar-minitar - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-03 12:11:14 +0530 (Fri, 03 Feb 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3778.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ruby-archive-tar-minitar on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 0.5.2-2+deb8u1.

We recommend that you upgrade your ruby-archive-tar-minitar packages." );
	script_tag( name: "summary", value: "Michal Marek discovered that
ruby-archive-tar-minitar, a Ruby library that provides the ability to deal with
POSIX tar archive files, is prone to a directory traversal vulnerability. An
attacker can take advantage of this flaw to overwrite arbitrary files during
archive extraction via a .. (dot dot) in an extracted filename." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ruby-archive-tar-minitar", ver: "0.5.2-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

