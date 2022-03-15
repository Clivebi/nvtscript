if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891641" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2016-4570", "CVE-2016-4571", "CVE-2018-20004" );
	script_name( "Debian LTS: Security Advisory for mxml (DLA-1641-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-25 00:00:00 +0100 (Fri, 25 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-16 16:28:00 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00018.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mxml on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.6-2+deb8u1.

We recommend that you upgrade your mxml packages." );
	script_tag( name: "summary", value: "Several stack exhaustion conditions were found in mxml that can easily
crash when parsing xml files.

CVE-2016-4570

The mxmlDelete function in mxml-node.c allows remote attackers to
cause a denial of service (stack consumption) via crafted xml file.

CVE-2016-4571

The mxml_write_node function in mxml-file.c allows remote attackers
to cause a denial of service (stack consumption) via crafted xml
file

CVE-2018-20004

A stack-based buffer overflow in mxml_write_node via vectors
involving a double-precision floating point number." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmxml-dev", ver: "2.6-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmxml1", ver: "2.6-2+deb8u1", rls: "DEB8" ) )){
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

