if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703635" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2014-9906", "CVE-2015-8949" );
	script_name( "Debian Security Advisory DSA 3635-1 (libdbd-mysql-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-04 16:27:17 +0530 (Thu, 04 Aug 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3635.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libdbd-mysql-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 4.028-2+deb8u1.

We recommend that you upgrade your libdbd-mysql-perl packages." );
	script_tag( name: "summary", value: "Two use-after-free vulnerabilities were
discovered in DBD::mysql, a Perl DBI driver for the MySQL database server. A remote
attacker can take advantage of these flaws to cause a denial-of-service against an
application using DBD::mysql (application crash), or potentially to
execute arbitrary code with the privileges of the user running the
application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libdbd-mysql-perl", ver: "4.028-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

