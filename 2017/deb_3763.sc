if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703763" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2016-7068" );
	script_name( "Debian Security Advisory DSA 3763-1 (pdns-recursor - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-13 00:00:00 +0100 (Fri, 13 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3763.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "pdns-recursor on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.6.2-2+deb8u3.

We recommend that you upgrade your pdns-recursor packages." );
	script_tag( name: "summary", value: "Florian Heinz and Martin Kluge reported
that pdns-recursor, a recursive DNS server, parses all records present in a query
regardless of whether they are needed or even legitimate, allowing a remote, unauthenticated
attacker to cause an abnormal CPU usage load on the pdns server,
resulting in a partial denial of service if the system becomes
overloaded." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pdns-recursor", ver: "3.6.2-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-recursor-dbg", ver: "3.6.2-2+deb8u3", rls: "DEB8" ) ) != NULL){
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

