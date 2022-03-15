if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892011" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2016-6296" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2019-11-27 03:00:15 +0000 (Wed, 27 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for xmlrpc-epi (DLA-2011-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2011-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xmlrpc-epi'
  package(s) announced via the DLA-2011-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue in xmlrpc-epi, an XML-RPC request serialisation/deserialisation
library, has been found.

An integer signedness error in the simplestring_addn function in
simplestring.c in xmlrpc-epi could be used for a heap based buffer
overflow and possibly execution of arbitrary code." );
	script_tag( name: "affected", value: "'xmlrpc-epi' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.54.2-1.1+deb8u1.

We recommend that you upgrade your xmlrpc-epi packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc-epi-dev", ver: "0.54.2-1.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc-epi0", ver: "0.54.2-1.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc-epi0-dbg", ver: "0.54.2-1.1+deb8u1", rls: "DEB8" ) )){
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
exit( 0 );

