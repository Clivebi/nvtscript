if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892078" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-17570" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-16 19:15:00 +0000 (Wed, 16 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-01-31 04:00:09 +0000 (Fri, 31 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for libxmlrpc3-java (DLA-2078-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00033.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2078-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/949089" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxmlrpc3-java'
  package(s) announced via the DLA-2078-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An untrusted deserialization was found in the
org.apache.xmlrpc.parser.XmlRpcResponseParser:addResult method of Apache
XML-RPC (aka ws-xmlrpc) library. A malicious XML-RPC server could target
a XML-RPC client causing it to execute arbitrary code.

Clients that expect to get server-side exceptions need to set the
enabledForExceptions property to true in order to process serialized
exception messages again." );
	script_tag( name: "affected", value: "'libxmlrpc3-java' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.1.3-7+deb8u1.

We recommend that you upgrade your libxmlrpc3-java packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc3-client-java", ver: "3.1.3-7+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc3-common-java", ver: "3.1.3-7+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc3-java-doc", ver: "3.1.3-7+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxmlrpc3-server-java", ver: "3.1.3-7+deb8u1", rls: "DEB8" ) )){
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

